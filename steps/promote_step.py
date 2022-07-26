import os
import sys
import logging

import glci.model
import glci.util
import glci.s3
import publish

parsable_to_int = str

logger = logging.getLogger(__name__)


def promote_single_step(
    cicd_cfg_name: str,
    gardenlinux_committish: str,
    architecture: str,
    platform: str,
    gardenlinux_epoch: parsable_to_int,
    modifiers: str,
    version: str,
    build_targets: str,
):
    cicd_cfg = glci.util.cicd_cfg(cfg_name=cicd_cfg_name)
    build_target_set = glci.model.BuildTarget.set_from_str(build_targets)

    if glci.model.BuildTarget.PUBLISH not in build_target_set:
        logger.info(f'build target {glci.model.BuildTarget.PUBLISH=} not specified - exiting now')
        sys.exit(0)

    find_release = glci.util.preconfigured(
        func=glci.util.find_release,
        cicd_cfg=cicd_cfg,
    )

    if platform not in glci.model.platform_names():
        raise ValueError(f'invalid value {platform=}')

    modifiers = glci.model.normalised_modifiers(
        platform=platform,
        modifiers=modifiers.split(','),
    )

    release_manifest = find_release(
        release_identifier=glci.model.ReleaseIdentifier(
            build_committish=gardenlinux_committish,
            version=version,
            gardenlinux_epoch=int(gardenlinux_epoch),
            architecture=glci.model.Architecture(architecture),
            platform=platform,
            modifiers=tuple(modifiers),
        ),
    )

    if not release_manifest:
        logger.info(f'No release-manifest found for {modifiers=}')
        exit(0)
        raise ValueError('no release-manifest found')

    if release_manifest.published_image_metadata is not None:
        # XXX should actually check for completeness - assume for now there is
        # transactional semantics in place
        logger.info('artifacts were already published - exiting now')
        sys.exit(0)

    # for AWS partitions (e.g. AWS-CN) the source-file needs to be in a bucket that is part
    # of that partition.
    if release_manifest.platform == 'aws':
        for aws_cfg_name in cicd_cfg.publish.aws.aws_cfg_names:
            if aws_cfg_name == cicd_cfg.build.aws_cfg_name:
                continue

            glci.s3._transport_release_artifact(
                release_manifest=release_manifest,
                source_cfg_name=cicd_cfg.build.aws_cfg_name,
                destination_cfg_name=aws_cfg_name,
                platform=platform,
            )

    new_manifest = publish.publish_image(
        release=release_manifest,
        cicd_cfg=cicd_cfg,
    )

    # the (modified) release manifest contains the publishing resource URLs - re-upload to persist
    upload_release_manifest = glci.util.preconfigured(
        func=glci.util.upload_release_manifest,
        cicd_cfg=cicd_cfg,
    )

    manifest_key = new_manifest.canonical_release_manifest_key()

    upload_release_manifest(
        key=manifest_key,
        manifest=new_manifest,
    )


def promote_step(
    cicd_cfg_name: str,
    flavour_set_name: str,
    build_targets: str,
    gardenlinux_epoch: parsable_to_int,
    gardenlinux_committish: str,
    version: str,
    promote_target: str,
    manifest_set_key_result: str,
):
    cicd_cfg = glci.util.cicd_cfg(cfg_name=cicd_cfg_name)
    flavour_set = glci.util.flavour_set(flavour_set_name)
    flavours = tuple(flavour_set.flavours())
    build_type: glci.model.BuildType = glci.model.BuildType(promote_target)
    build_target_set = glci.model.BuildTarget.set_from_str(build_targets)

    # write result so thet we always have a result:
    with open(manifest_set_key_result, 'w') as f:
       pass

    if glci.model.BuildTarget.MANIFEST not in build_target_set:
        logger.info(f'build target {glci.model.BuildTarget.MANIFEST=} not specified - exiting now')
        sys.exit(0)

    find_releases = glci.util.preconfigured(
      func=glci.util.find_releases,
      cicd_cfg=cicd_cfg,
    )

    releases = tuple(
      find_releases(
        flavour_set=flavour_set,
        build_committish=gardenlinux_committish,
        version=version,
        gardenlinux_epoch=int(gardenlinux_epoch),
      )
    )

    # ensure all previous tasks really were successful
    is_complete = len(releases) == len(flavours)
    if not is_complete:
        logger.info(f"Found: {len(releases)=}")
        logger.info(f"Expected: {len(flavours)=}")
        logger.error('release was not complete - will not publish (this indicates a bug!)')
        sys.exit(0)  # do not signal an error

    logger.debug(build_target_set)

    # if this line is reached, the release has been complete
    # now create and publish manifest-set

    upload_release_manifest_set = glci.util.preconfigured(
        func=glci.util.upload_release_manifest_set,
        cicd_cfg=cicd_cfg,
    )

    manifest_set = glci.model.ReleaseManifestSet(
        manifests=releases,
        flavour_set_name=flavour_set.name,
    )

    manifest_path = os.path.join(
        glci.model.ReleaseManifestSet.release_manifest_set_prefix,
        build_type.value,
        glci.util.release_set_manifest_name(
            build_committish=gardenlinux_committish,
            gardenlinux_epoch=gardenlinux_epoch,
            version=version,
            flavour_set_name=flavour_set.name,
            build_type=build_type,
            with_timestamp=True,
        ),
    )

    upload_release_manifest_set(
        key=manifest_path,
        manifest_set=manifest_set,
    )

    logger.info(f'uploaded manifest-set: {manifest_path=}')

    with open(manifest_set_key_result, 'w') as f:
       f.write(manifest_path)
