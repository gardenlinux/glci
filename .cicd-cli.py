#!/usr/bin/env python3

import argparse
import dataclasses
import enum
import typing

import git
import logging
import os
import pprint
import sys
import yaml

import component_descriptor as cd

import ccc.oci
import ocm.upload
import cnudie.retrieve
import version as cc_version

logger = logging.getLogger('gardenlinux-cli')

own_dir = os.path.abspath(os.path.dirname(__file__))
ci_dir = os.path.join(own_dir, 'ci')

sys.path.insert(1, ci_dir)

import glci.aws   # noqa: E402
import glci.util  # noqa: E402
import glci.model # noqa: E402
import paths      # noqa: E402


# see also:
# https://stackoverflow.com/questions/43968006/support-for-enum-arguments-in-argparse/55500795
class EnumAction(argparse.Action):
    """
    Argparse action for handling Enums
    """
    def __init__(self, **kwargs):
        # Pop off the type value
        enum_type: typing.Any = kwargs.pop("type", None)

        # Ensure an Enum subclass is provided
        if enum_type is None:
            raise ValueError("type must be assigned an Enum when using EnumAction")
        if not issubclass(enum_type, enum.Enum):
            raise TypeError("type must be an Enum when using EnumAction")

        # Generate choices from the Enum
        kwargs.setdefault("choices", tuple(e.value for e in enum_type))

        super(EnumAction, self).__init__(**kwargs)

        self._enum = enum_type

    def __call__(self, parser, namespace, values, option_string=None):
        # Convert value back into an Enum
        value = self._enum(values)
        setattr(namespace, self.dest, value)


def _add_flavourset_args(parser):
    parser.add_argument(
        '--flavourset',
        action='append',
        dest='flavoursets',
        default=[],
        help='if set, only specified flavoursets will be published (default: publish all)',
    )
    parser.add_argument(
        '--flavours-file',
        default=None,
    )


def _flavoursets(parsed):
    if parsed.flavours_file:
        flavours_path = parsed.flavours_file
    else:
        flavours_path = paths.flavour_cfg_path

    if parsed.flavoursets:
        flavour_sets = [glci.util.flavour_set(
            flavour_set_name=flavourset,
            build_yaml=flavours_path,
        ) for flavourset in parsed.flavoursets]
    else:
        flavour_sets = glci.util.flavour_sets(build_yaml=flavours_path)

    return flavour_sets


def _add_publishing_cfg_args(
        parser,
        default: str = 'default'
):
    parser.add_argument('--cfg-name', default=default)


def _publishing_cfg(parsed):
    cfg = glci.util.publishing_cfg(cfg_name=parsed.cfg_name)

    return cfg

def ls_manifests():
    parser = argparse.ArgumentParser()

    _add_flavourset_args(parser)
    _add_publishing_cfg_args(parser)

    parser.add_argument(
        "--version",
        default=None,
        help="if given, filters for a specific version",
    )
    parser.add_argument(
        '--version-prefix',
        default=None,
        help='if given, filter for versions of given prefix',
    )
    parser.add_argument(
        '--print',
        default='all',
        choices=('all', 'versions', 'versions-and-commits', 'greatest'),
    )
    parser.add_argument(
        '--yaml',
        nargs=1,
        help="write output to specified yaml file"
    )

    parsed = parser.parse_args()

    flavour_sets = _flavoursets(parsed)
    flavours = []
    for fs in flavour_sets:
        flavours.extend(fs.flavours())

    version = parsed.version

    def iter_manifest_prefixes():
        key_prefix = glci.model.ReleaseIdentifier.manifest_key_prefix
        version_prefix = parsed.version_prefix

        for f_ in flavours:
            cname = glci.model.canonical_name(
                platform=f_.platform,
                mods=f_.modifiers,
                architecture=f_.architecture,
                version=version,
            )
            prefix_ = f'{key_prefix}/{cname}'

            if version_prefix:
                prefix_ = f'{prefix_}-{version_prefix}'

            yield prefix_

    cfg = _publishing_cfg(parsed)
    s3_client = glci.aws.session(cfg.origin_buildresult_bucket.aws_cfg_name).client('s3')

    manifests = list()
    for prefix in iter_manifest_prefixes():
        matching_manifests = s3_client.list_objects_v2(
            Bucket=cfg.origin_buildresult_bucket.bucket_name,
            Prefix=prefix,
        )
        if matching_manifests['KeyCount'] == 0:
            continue
        for entry in matching_manifests['Contents']:
            key = entry['Key']
            _, version, commit = key.rsplit('-', 2)
            if version in ["experimental", "today"] or commit == "local":
                continue
            epoch, _ = version.split('.')
            s = glci.model.S3Manifest(
                manifest_key=key,
                epoch=epoch,
                version=version,
                committish=commit
            )
            manifests.append(s)

    manifests.sort(key=lambda v: cc_version.greatest_version([cc_version.parse_to_semver(v.version)]))

    if parsed.print == 'greatest':
        m = manifests.pop()
        if parsed.yaml:
            version = glci.model.S3ManifestVersion(
                epoch=m.epoch,
                version=m.version,
                committish=m.committish
            )
            with open(parsed.yaml[0], "w") as f:
                f.write(yaml.safe_dump(dataclasses.asdict(version)))
        else:
            print(f"{m.version} {m.committish}")
    else:
        for m in manifests:
            if parsed.print == 'all':
                print(f"{m.manifest_key}")
            elif parsed.print == 'versions':
                print(f"{m.version}")
            elif parsed.print == 'versions-and-commits':
                print(f"{m.version} {m.committish}")


def publish_release_set():
    import publish      # late import because unneeded for the other funtions
    import replicate    # late import because unneeded for the other funtions

    parser = argparse.ArgumentParser(
        description='run all sub-steps for publishing gardenlinux to all target hyperscalers',
    )
    _add_flavourset_args(parser)
    _add_publishing_cfg_args(parser)

    phase_sync = 'sync-images'
    phase_publish = 'publish-images'
    phase_component_descriptor = 'publish-component-descriptor'

    all_phases = phase_sync, phase_publish, phase_component_descriptor

    parser.add_argument(
        '--version',
    )
    parser.add_argument(
        '--commit',
    )
    parser.add_argument(
        '--on-absent-cfg',
        choices=('warn', 'fail'),
        default='warn',
        help='behaviour upon absent publishing-cfg (see publishing-cfg.yaml)',
    )
    parser.add_argument(
        '--platform',
        action='append',
        dest='platforms',
        default=[],
        help='if set, only specified platforms will be published to (default: publish to all)',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        default=False,
        help='publish images, even if already present according to release-manifests',
    )
    parser.add_argument(
        '--print-manifest',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--print-component-descriptor',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--phase',
        default=None,
        choices=(
            phase_sync,
            phase_publish,
            phase_component_descriptor,
        ),
        help='if set, only run until specified phase (default: run all)',
    )
    parser.add_argument(
        '--skip-previous-phases',
        action='store_true',
        default=False,
        help='if --phase is given, skip previous phases (for debugging purposes)',
    )
    parser.add_argument(
        "--version-file",
        nargs=1,
        help="read version and committish from given YAML file"
    )

    parsed = parser.parse_args()

    version = None
    commit = None

    if not bool(parsed.version_file):
        if not bool(parsed.version):
            logger.fatal('--version must be passed')
            exit(1)

        if not bool(parsed.commit):
            logger.fatal('--commit must be passed')
            exit(1)

        version = parsed.version
        commit = parsed.commit

    else:
        with open(parsed.version_file[0]) as f:
            version_yaml = yaml.safe_load(f)
            version = version_yaml['version']
            commit = version_yaml['committish']

    cfg = _publishing_cfg(parsed)

    flavour_sets = _flavoursets(parsed)

    if len(commit) != 40:
        repo = git.Repo(path=paths.gardenlinux_dir)
        commit = repo.git.rev_parse(commit)
        logger.info(f'expanded commit to {commit}')

    flavour_set_names = [flavour_set.name for flavour_set in flavour_sets]
    logger.info(
        f'Publishing gardenlinux {version}@{commit} ({flavour_set_names})\n'
    )

    if not (phase := parsed.phase):
        phases_to_run = all_phases
    else:
        if phase == phase_sync:
            phases_to_run = phase_sync,
        elif phase == phase_publish:
            if parsed.skip_previous_phases:
                phases_to_run = phase_publish,
            else:
                phases_to_run = phase_sync, phase_publish
        elif phase == phase_component_descriptor:
            if parsed.skip_previous_phases:
                phases_to_run = phase_component_descriptor,
            else:
                phases_to_run = all_phases
        else:
            raise NotImplementedError(phase)

    logger.info('phases to run:\n- ' + '\n- '.join(phases_to_run))
    print()

    def start_phase(phase_name):
        phase_logger_ = logging.getLogger(phase_name)
        phase_logger_.info(20 * '=')
        phase_logger_.info(f'Starting Phase {phase_name}')
        phase_logger_.info(20 * '=')
        print()
        return phase_logger_


    def end_phase(phase_name):
        phase_logger_ = logging.getLogger(phase_name)
        phase_logger_.info(20 * '=')
        phase_logger_.info(f'End of Phase {phase_name}')
        phase_logger_.info(20 * '=')
        print()
        if (p := parsed.phase) and p == phase_name:
            phase_logger_.info(f'will stop here, as {phase_name} was passed as final phase via ARGV')
            exit(0)

    phase_logger = start_phase('sync-images')

    source_manifest_bucket = cfg.source_manifest_bucket
    target_manifest_buckets = tuple(cfg.target_manifest_buckets)
    if not target_manifest_buckets:
        target_manifest_buckets = (source_manifest_bucket,)

    s3_session = glci.aws.session(source_manifest_bucket.aws_cfg_name)
    s3_client = s3_session.client('s3')

    release_manifests = []
    for fs in flavour_sets:
        release_manifests.extend(
            glci.util.find_releases(
                s3_client=s3_client,
                bucket_name=source_manifest_bucket.bucket_name,
                fset=fs,
                build_committish=commit,
                version=version,
                gardenlinux_epoch=int(version.split('.')[0]),
            )
        )

    if not release_manifests:
        phase_logger.fatal(
            f'did not find any release-manifests for {version=} {commit=}',
        )
        phase_logger.fatal(
            'hint: use `ls-manifests` command to find valid choices for version | commit'
        )
        exit(1)
    phase_logger.info(f'found {len(release_manifests)=}')

    if phase_sync in phases_to_run:
        run_sync = True
    else:
        run_sync = False

    if run_sync:
        replicas_present = replicate.check_replicated_image_blobs(
            publishing_cfg=cfg,
            release_manifests=release_manifests,
        )

        if not replicas_present:
            phase_logger.error(f"not all replicas are present - check the Garden Linux build and upload-to-S3 job")
            exit(1)
    else:
        phase_logger.info('skipping sync-images (--skip-previous-phases)')

    end_phase(phase_sync)

    phase_logger = start_phase(phase_publish)

    phase_logger.info('validating publishing-cfg')

    for manifest in release_manifests:
        target_cfg = cfg.target(platform=manifest.platform, absent_ok=True)
        if not target_cfg:
            if (on_absent := parsed.on_absent_cfg) == 'warn':
                phase_logger.warning(
                    f'no cfg for {manifest.platform=} - will NOT publish!'
                )
                continue
            elif on_absent == 'fail':
                phase_logger.fatal(
                    f'no cfg for {manifest.platform=} - aborting'
                )
            else:
                raise ValueError(on_absent) # programming error

    phase_logger.info('publishing-cfg was found to be okay - starting publishing now')

    if phase_publish in phases_to_run:
        run_publish = True
    else:
        run_publish = False

    for idx, manifest in enumerate(release_manifests):
        if not run_publish:
            continue

        if parsed.platforms and not manifest.platform in parsed.platforms:
            logger.info(f'skipping {manifest.platform} (filter was set via ARGV)')
            continue

        name = manifest.release_identifier().canonical_release_manifest_key()
        phase_logger.info(name)

        target_cfg = cfg.target(platform=manifest.platform, absent_ok=True)
        if not target_cfg: # we already validated above that user is okay to skip
            continue

        if parsed.print_manifest:
            pprint.pprint(manifest)

        if manifest.published_image_metadata:
            if not parsed.force:
                phase_logger.info('already published -> skipping publishing phase')
                continue
            else:
                phase_logger.warning('force-publishing')

        phase_logger.info(f'will publish image to {manifest.platform}')

        updated_manifest = publish.publish_image(
            release=manifest,
            publishing_cfg=cfg,
        )
        release_manifests[idx] = updated_manifest

        phase_logger.info(f"{idx=}, {target_manifest_buckets=}")

        for target_manifest_bucket in target_manifest_buckets:
            target = f'{target_manifest_bucket.bucket_name}/{manifest.s3_key}'
            phase_logger.info(f'updating release-manifest at {target}')

            glci.util.upload_release_manifest(
                s3_client=s3_client,
                bucket_name=target_manifest_bucket.bucket_name,
                key=manifest.s3_key,
                manifest=updated_manifest,
            )

        phase_logger.info(f'image publishing for {manifest.platform} succeeded')

    if not run_publish:
        phase_logger.info('skipped image-publishing (--skip-previous-phases)')

    end_phase(phase_publish)

    phase_logger = start_phase(phase_component_descriptor)

    if parsed.platforms:
        phase_logger.error('must not filter platforms if publishing component-descriptor')
        phase_logger.error('component-descriptor is intended to always contain full release-set')
        exit(1)

    phase_logger.info('generating component-descriptor')
    component_descriptor = cd.component_descriptor(
        version=version,
        commit=commit,
        publishing_cfg=cfg,
        release_manifests=release_manifests,
    )

    if parsed.print_component_descriptor:
        pprint.pprint(component_descriptor)

    oci_ref = component_descriptor.component.current_ocm_repo.oci_ref
    component_name = component_descriptor.component.name
    component_version = component_descriptor.component.version

    phase_logger.info('publishing component-descriptor')
    on_exist=ocm.upload.UploadMode.OVERWRITE if cfg.ocm.overwrite_component_descriptor else ocm.upload.UploadMode.SKIP
    phase_logger.info(f'{oci_ref=} {component_name=} {component_version=} {on_exist=}')

    oci_client = ccc.oci.oci_client()

    ocm.upload.upload_component_descriptor(
        component_descriptor=component_descriptor,
        oci_client=oci_client,
        on_exist=on_exist
    )

    end_phase(phase_component_descriptor)


def cleanup_release_set():
    import cleanup # late import because it is unneeded for the other functions in this swiss-army-knife of a tool
    pp = pprint.PrettyPrinter(indent=4)

    parser = argparse.ArgumentParser(
        description='clean a release set from all target hyperscalers',
    )
    _add_publishing_cfg_args(parser, default="gardener-integration-test")
    _add_flavourset_args(parser)

    parser.add_argument(
        '--version',
    )
    parser.add_argument(
        '--commit',
        help='committish of the release to be cleaned (if not specified, it is obtained from the component descriptor)',
        dest='committish'
    )
    parser.add_argument(
        '--skip-component-descriptor',
        help='just delete artefacts based on their release manifests, do not touch component descriptors',
        dest='skip_component_descriptor',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '--ocm-repo',
        help='the component-repo to retrieve gardenlinux-component-descriptor from',
        default=None,
        required=False,
    )
    parser.add_argument(
        '--platform',
        action='append',
        dest='platforms',
        default=[],
        help='if set, only specified platforms will be published to (default: publish to all)',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        default=False,
        help='dry-run, only pretend to delete artefacts but do not actually do it',
    )
    parser.add_argument(
        '--print-manifest',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        '--print-component-descriptor',
        action='store_true',
        default=False,
    )
    parser.add_argument(
        "--version-file",
        nargs=1,
        help="read version from given YAML file"
    )

    parsed = parser.parse_args()

    if bool(parsed.version_file):
        with open(parsed.version_file[0]) as f:
            input_ = yaml.safe_load(f)
            version = input_['version']
    elif bool(parsed.version):
        version = parsed.version
    else:
        raise RuntimeError(f"need to provide either --version or --version-file parameter")

    cfg = _publishing_cfg(parsed)

    commit = None

    if parsed.skip_component_descriptor and parsed.committish:
        commit = parsed.committish
        if len(commit) != 40:
            repo = git.Repo(path=paths.gardenlinux_dir)
            commit = repo.git.rev_parse(commit)
            logger.info(f'expanded commit to {commit}')
    else:
        if not parsed.ocm_repo:
            ocm_repo_base_url = cfg.ocm.ocm_repository
        else:
            ocm_repo_base_url = parsed.ocm_repo

        oci_client = ccc.oci.oci_client()

        component_descriptor_lookup = cnudie.retrieve.create_default_component_descriptor_lookup(
            ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_repo_base_url),
            oci_client=oci_client
        )

        gardenlinux_component = component_descriptor_lookup(('github.com/gardenlinux/gardenlinux', version)).component

        if parsed.print_component_descriptor:
            pp.pprint(gardenlinux_component)

        for s in gardenlinux_component.sources:
            if s.name != "gardenlinux":
                continue
            commit = s.access.commit
            break

    target_manifest_buckets = tuple(cfg.target_manifest_buckets)
    if len(target_manifest_buckets) == 0:
        target_manifest_buckets = (cfg.source_manifest_bucket,)
    elif len(target_manifest_buckets) > 1:
        raise RuntimeError(f"more than one target manifest buckets specified - this is currently not supported")

    s3_session = glci.aws.session(target_manifest_buckets[0].aws_cfg_name)
    s3_client = s3_session.client('s3')

    flavour_sets = _flavoursets(parsed)
    release_manifests = []
    for fs in flavour_sets:
        release_manifests.extend(
            glci.util.find_releases(
                s3_client=s3_client,
                bucket_name=target_manifest_buckets[0].bucket_name,
                fset=fs,
                build_committish=commit,
                version=version,
                gardenlinux_epoch=int(version.split('.')[0]),
            )
        )

    logger.info(f"found {len(release_manifests)} release manifests in bucket {target_manifest_buckets[0].bucket_name}")

    # todo: sanity check that it matches the published metadata in the component descriptor

    for idx, manifest in enumerate(release_manifests):
        if parsed.platforms and not manifest.platform in parsed.platforms:
            logger.info(f'skipping {manifest.platform} (filter was set via ARGV)')
            continue

        if not manifest.published_image_metadata:
            logger.info(f"manifest for platform {manifest.platform}/{manifest.architecture.value} does not contain publishing metadata, skipping")
            continue

        target_cfg = cfg.target(platform=manifest.platform, absent_ok=False)
        if not target_cfg:
            continue

        logger.info(f'will cleanup images from {manifest.platform}/{manifest.architecture.value}')

        updated_manifest = cleanup.cleanup_image(
            release=manifest,
            publishing_cfg=cfg,
            dry_run=parsed.dry_run
        )

        if parsed.print_manifest:
            pprint.pprint(updated_manifest)

        release_manifests[idx] = updated_manifest

        for target_manifest_bucket in target_manifest_buckets:
            target = f'{target_manifest_bucket.bucket_name}/{manifest.s3_key}'
            if parsed.dry_run:
                logger.warning(f'DRY RUN: would update release-manifest at {target}')
                continue
            else:
                logger.info(f'updating release-manifest at {target}')

                glci.util.upload_release_manifest(
                    s3_client=s3_client,
                    bucket_name=target_manifest_bucket.bucket_name,
                    key=manifest.s3_key,
                    manifest=updated_manifest,
                )

        logger.info(f'cleaning up images for {manifest.platform}/{manifest.architecture.value} succeeded')


def main():
    cmd_name = os.path.basename(sys.argv[0]).replace('-', '_')

    module_symbols = sys.modules[__name__]

    func = getattr(module_symbols, cmd_name, None)

    if not func:
        print(f'ERROR: {cmd_name} is not defined')
        sys.exit(1)

    func()


if __name__ == '__main__':
    main()
