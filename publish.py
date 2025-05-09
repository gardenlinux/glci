#!/usr/bin/env python3

"""
Promotes the specified build results (represented by build result manifests in S3).

An example being the promotion of a build snapshot to a daily build.
"""

import logging.config

import cleanup

import ci.util

import glci.aws
import glci.az
import glci.gcp
import glci.util
import glci.model as gm
from glci.model import OnlineReleaseManifest

logger = logging.getLogger(__name__)


def publish_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> gm.OnlineReleaseManifest:
    logger.info(f'running release for {release.platform=}')

    if release.platform == 'ali':
        publish_function = _publish_alicloud_image
        cleanup_function = cleanup.cleanup_alicloud_images
    elif release.platform == 'aws':
        publish_function = _publish_aws_image
        cleanup_function = cleanup.cleanup_aws_images
    elif release.platform == 'gcp':
        publish_function = _publish_gcp_image
        cleanup_function = cleanup.cleanup_gcp_images
    elif release.platform == 'azure':
        publish_function = _publish_azure_image
        cleanup_function = None
    elif release.platform == 'openstack':
        publish_function = _publish_openstack_image
        cleanup_function = cleanup.cleanup_openstack_images
    elif release.platform == 'openstackbaremetal':
        publish_function = _publish_openstack_image
        cleanup_function = cleanup.cleanup_openstack_images
    elif release.platform == 'oci':
        publish_function = _publish_oci_image
        cleanup_function = None
    else:
        logger.warning(f'do not know how to publish {release.platform=}, yet')
        return release

    try:
        return publish_function(release, publishing_cfg)
    except:
        import traceback
        traceback.print_exc()
        if not cleanup_function is None:
            cleanup_function(release, publishing_cfg)
        else:
            logger.warning(f'do not know how to cleanup {release.platform=}')
        raise


def _publish_alicloud_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> gm.OnlineReleaseManifest:
    import glci.alicloud
    import glci.aws
    aliyun_cfg = publishing_cfg.target(release.platform)
    alicloud_cfg_name = aliyun_cfg.aliyun_cfg_name

    oss_auth = glci.alicloud.oss_auth(alicloud_cfg=alicloud_cfg_name)
    acs_client = glci.alicloud.acs_client(alicloud_cfg=alicloud_cfg_name)

    maker = glci.alicloud.AlicloudImageMaker(
        oss_auth,
        acs_client,
        release,
        aliyun_cfg,
    )

    s3_client = glci.aws.session(
        publishing_cfg.origin_buildresult_bucket.aws_cfg_name,
    ).client('s3')
    maker.cp_image_from_s3(s3_client)
    return maker.make_image()


def _publish_aws_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> gm.OnlineReleaseManifest:
    aws_publishing_cfg: gm.PublishingTargetAWS = publishing_cfg.target(platform=release.platform)

    return glci.aws.upload_and_register_gardenlinux_image(
        aws_publishing_cfg=aws_publishing_cfg,
        publishing_cfg=publishing_cfg,
        release=release,
    )


def _publish_azure_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> OnlineReleaseManifest:
    azure_publishing_cfgs: list[gm.PublishingTargetAzure] = publishing_cfg.target_multi(platform=release.platform)

    for azure_publishing_cfg in azure_publishing_cfgs:
        logger.info(f"targetting {azure_publishing_cfg.cloud}")

        aws_session = glci.aws.session(
            publishing_cfg.buildresult_bucket(azure_publishing_cfg.buildresult_bucket).aws_cfg_name
                if azure_publishing_cfg.buildresult_bucket
                else publishing_cfg.origin_buildresult_bucket.aws_cfg_name,
        )
        s3_client = aws_session.client('s3')
        cfg_factory = ci.util.ctx().cfg_factory()

        storage_account_cfg = cfg_factory.azure_storage_account(
            azure_publishing_cfg.storage_account_cfg_name,
        )
        storage_account_cfg_serialized = gm.AzureStorageAccountCfg(
            storage_account_name=storage_account_cfg.storage_account_name(),
            access_key=storage_account_cfg.access_key(),
            container_name=storage_account_cfg.container_name(),
            container_name_sig=storage_account_cfg.container_name_sig(),
            endpoint_suffix=azure_publishing_cfg.cloud.storage_endpoint()
        )
        # get credential object from configured user and secret
        azure_principal = cfg_factory.azure_service_principal(
            cfg_name=azure_publishing_cfg.service_principal_cfg_name,
        )
        azure_principal_serialized =  gm.AzureServicePrincipalCfg(
            tenant_id=azure_principal.tenant_id(),
            client_id=azure_principal.client_id(),
            client_secret=azure_principal.client_secret(),
            subscription_id=azure_principal.subscription_id(),
        )

        shared_gallery_cfg = cfg_factory.azure_shared_gallery(
            cfg_name=azure_publishing_cfg.gallery_cfg_name,
        )
        shared_gallery_cfg_serialized = gm.AzureSharedGalleryCfg(
            resource_group_name=shared_gallery_cfg.resource_group_name(),
            gallery_name=shared_gallery_cfg.gallery_name(),
            location=shared_gallery_cfg.location(),
            published_name=shared_gallery_cfg.published_name(),
            description=shared_gallery_cfg.description(),
            eula=shared_gallery_cfg.eula(),
            release_note_uri=shared_gallery_cfg.release_note_uri(),
            identifier_publisher=shared_gallery_cfg.identifier_publisher(),
            identifier_offer=shared_gallery_cfg.identifier_offer(),
            identifier_sku=shared_gallery_cfg.identifier_sku(),
            regions=azure_publishing_cfg.gallery_regions,
        )

        release = glci.az.publish_azure_image(
            s3_client=s3_client,
            release=release,
            service_principal_cfg=azure_principal_serialized,
            storage_account_cfg=storage_account_cfg_serialized,
            shared_gallery_cfg=shared_gallery_cfg_serialized,
            hyper_v_generations=azure_publishing_cfg.hyper_v_generations,
            azure_cloud=azure_publishing_cfg.cloud,
        )

    return release


def _publish_gcp_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> gm.OnlineReleaseManifest:
    gcp_publishing_cfg: gm.PublishingTargetGCP = publishing_cfg.target(release.platform)
    cfg_factory = ci.util.ctx().cfg_factory()
    gcp_cfg = cfg_factory.gcp(gcp_publishing_cfg.gcp_cfg_name)
    storage_client = glci.gcp.cloud_storage_client(gcp_cfg)
    s3_client = glci.aws.session(
        publishing_cfg.origin_buildresult_bucket.aws_cfg_name,
    ).client('s3')

    compute_client = glci.gcp.authenticated_build_func(gcp_cfg)('compute', 'v1')

    return glci.gcp.upload_and_publish_image(
        storage_client=storage_client,
        s3_client=s3_client,
        compute_client=compute_client,
        gcp_project_name=gcp_cfg.project(),
        release=release,
        gcp_publishing_cfg=gcp_publishing_cfg,
    )


def _publish_oci_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
    release_build: bool = True,
) -> gm.OnlineReleaseManifest:
    import glci.oci
    import ccc.oci

    oci_publishing_cfg = publishing_cfg.target(release.platform)

    oci_client = ccc.oci.oci_client()
    s3_client = glci.aws.session(
        publishing_cfg.origin_buildresult_bucket.aws_cfg_name,
    ).client('s3')

    return glci.oci.publish_image(
        release=release,
        publishing_cfg=oci_publishing_cfg,
        s3_client=s3_client,
        oci_client=oci_client,
        release_build=release_build,
    )


def _publish_openstack_image(
    release: gm.OnlineReleaseManifest,
    publishing_cfg: gm.PublishingCfg,
) -> gm.OnlineReleaseManifest:
    import glci.openstack_image
    import ci.util

    openstack_publishing_cfg: gm.PublishingTargetOpenstack = publishing_cfg.target(
        platform=release.platform,
    )

    cfg_factory = ci.util.ctx().cfg_factory()
    openstack_environments_cfg = cfg_factory.ccee(
        openstack_publishing_cfg.environment_cfg_name,
    )

    s3_bucket_access = {}
    for project in openstack_environments_cfg.projects():
        if openstack_publishing_cfg.cn_regions and project.region() in openstack_publishing_cfg.cn_regions.region_names:
            build_result_bucket = publishing_cfg.buildresult_bucket(openstack_publishing_cfg.cn_regions.buildresult_bucket)
            s3_bucket_access[project.region()] = (
                glci.aws.session(build_result_bucket.aws_cfg_name).client('s3'),
                build_result_bucket.bucket_name
            )
        else:
            s3_bucket_access[project.region()] = (
                glci.aws.session(publishing_cfg.origin_buildresult_bucket.aws_cfg_name).client('s3'),
                publishing_cfg.origin_buildresult_bucket.bucket_name
            )

    username = openstack_environments_cfg.credentials().username()
    password = openstack_environments_cfg.credentials().passwd()

    openstack_env_cfgs = tuple((
        gm.OpenstackEnvironment(
            project_name=project.name(),
            domain=project.domain(),
            region=project.region(),
            auth_url=project.auth_url(),
            username=username,
            password=password,
        ) for project in openstack_environments_cfg.projects()
            if not openstack_publishing_cfg.copy_regions
                or project.region() in openstack_publishing_cfg.copy_regions
    ))

    image_properties = openstack_publishing_cfg.image_properties

    return glci.openstack_image.upload_and_publish_image(
        s3_bucket_access=s3_bucket_access,
        openstack_environments_cfgs=openstack_env_cfgs,
        image_properties=image_properties,
        release=release,
        suffix=openstack_publishing_cfg.suffix,
        visibility=openstack_publishing_cfg.visibility
    )
