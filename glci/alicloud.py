import dataclasses
import datetime
import enum
import json
import logging
import tempfile
import time

import aliyunsdkcore.client
from aliyunsdkcore.client import AcsClient
from aliyunsdkecs.request.v20140526 import (
    CopyImageRequest,
    DeleteImageRequest,
    DescribeImagesRequest,
    DescribeRegionsRequest,
    ImportImageRequest,
    ModifyImageSharePermissionRequest
)
import ctx
import model.alicloud
import oss2

import glci.model
import glci.util

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
TIME_OUT = 120 * 60  # in seconds, 2h


class AlicloudImageStatus(enum.Enum):
    CREATING = "Creating"
    WAITING = "Waiting"
    AVAILABLE = "Available"
    UNAVAILABLE = "UnAvailable"
    CREATEFAILED = "CreateFailed"

    def __str__(self):
        return self.value

    @staticmethod
    def to_availbel_str_array() -> []:
        return [v.value for v in AlicloudImageStatus]


class AlicloudImageMaker:
    def __init__(
        self,
        oss2_auth: oss2.Auth,
        client: AcsClient,
        release: glci.model.OnlineReleaseManifest,
        publishing_cfg: glci.model.PublishingTargetAliyun,
    ):
        self.oss2_auth = oss2_auth
        self.acs_client = client
        self.release = release
        self.bucket_name =  publishing_cfg.oss_bucket_name
        self.region = publishing_cfg.aliyun_region
        self.regions_to_copy_to = publishing_cfg.copy_regions
        self.image_oss_key = f"gardenlinux-{self.release.version}.qcow2"
        self.image_name = f"gardenlinux-{self.release.canonical_release_manifest_key_suffix()}"

    # copy image from S3 to OSS
    def cp_image_from_s3(self, s3_client):

        ali_release_artifact = glci.util.vm_image_artefact_for_platform('ali')
        ali_release_artifact_path = self.release.path_by_suffix(ali_release_artifact)

        s3_bucket_key = ali_release_artifact_path.s3_key
        s3_bucket_name = ali_release_artifact_path.s3_bucket_name

        bucket = oss2.Bucket(
            self.oss2_auth,
            f"https://oss-{self.region}.aliyuncs.com",
            self.bucket_name,
        )

        if bucket.object_exists(key=self.image_oss_key):
            logger.info(f'blob already exists at {self.image_oss_key=} - skipping upload')
            return

        with tempfile.TemporaryFile() as tf:
            blob = s3_client.get_object(
                Bucket=s3_bucket_name,
                Key=s3_bucket_key,
            )['Body']

            while chunk := blob.read(4096):
                tf.write(chunk)

            tf.seek(0)

            logger.info(f"downloaded image from s3 {s3_bucket_name}/{s3_bucket_key}")
            logger.info(f"uploading to oss {self.bucket_name=} {self.image_oss_key=} {self.region=}")

            bucket.put_object(
                key=self.image_oss_key,
                data=tf,
            )

        logger.info(f"uploaded image to oss {self.bucket_name} {self.image_oss_key=}")

    # Import image from OSS and then copy it to other regions
    def make_image(self) -> glci.model.OnlineReleaseManifest:
        source_image_id = self.import_image()
        other_regions = self._list_regions()
        logger.info(f"begin to copy image to {other_regions=}")
        region_image_map = {}
        for region in other_regions:
            region_image_map[region] = self.copy_image(source_image_id, region)

        for region, image_id in region_image_map.items():
            self._wait_for_image(region, image_id)
            logger.info(f"finished copying {image_id=} to {region=}")

        region_image_map[self.region] = source_image_id

        self._share_images(region_image_map)

        # make release manifest
        published_images = tuple((glci.model.AlicloudPublishedImage(
            image_id=image_id,
            region_id=region,
            image_name=self.image_name,
        ) for region, image_id in region_image_map.items()))
        published_image_set = glci.model.AlicloudPublishedImageSet(
            published_alicloud_images=published_images)

        return dataclasses.replace(
            self.release, published_image_metadata=published_image_set)

    # Share image as a community image. The account should apply for whitelist
    def _share_images(self, region_image_map: dict):
        for region, image_id in region_image_map.items():
            self.acs_client.set_region_id(region)
            logger.info(
                f"share image ({region}/{image_id}) as a community image"
            )
            req = ModifyImageSharePermissionRequest.ModifyImageSharePermissionRequest()
            req.set_ImageId(image_id)

            try:
                req.set_IsPublic(True)
                self.acs_client.do_action_with_exception(req)
            except aliyunsdkcore.client.ServerException as se:
                if se.error_code == 'Image.Public' and 'is public' in se.message:
                    logger.info('image was already published - skipping')
                    continue
                print(f'debug: {se=} {se.error_code=} {se.message=}')
                raise se

        self.acs_client.set_region_id(self.region)

    def _del_image(self, region, image_id):
        logger.info(f"Delete image {self.image_name}/{image_id} in region {region}")
        self.acs_client.set_region_id(region)
        req = ModifyImageSharePermissionRequest.ModifyImageSharePermissionRequest()
        req.set_ImageId(image_id)
        req.set_IsPublic(False)
        self.acs_client.do_action_with_exception(req)
        req = DeleteImageRequest.DeleteImageRequest()
        req.set_ImageId(image_id)
        self.acs_client.do_action_with_exception(req)

    # delete images
    def delete_images(self, keep_going=True):
        did_raise = False
        regions = self._list_regions()
        regions.append(self.region)
        for region in regions:
            exist, image_id = self._check_image_existance(region, self.image_name)
            if exist:
                try:
                    self._del_image(region, image_id)
                except:
                    if keep_going:
                        did_raise = True
                        continue
                    raise

        if did_raise:
            raise

    # Import image from oss. Returns image id
    def import_image(self) -> str:
        exist, image_id = self._check_image_existance(self.region,
                                                      self.image_name)
        if exist:
            logger.info(
                f"found image {self.image_name} already exists in region {self.region}, the id is {image_id}, skip importing"
            )
            self._wait_for_image(self.region, image_id)
        else:
            logger.info(
                f"importing image {self.image_name} in region {self.region}")
            req = ImportImageRequest.ImportImageRequest()
            req.set_Description(self.image_name)
            req.set_Platform("Others Linux")
            req.set_ImageName(self.image_name)
            dev_map = [{
                "OSSBucket": self.bucket_name,
                "DiskImageSize": "20",
                "Format": "qcow2",
                "OSSObject": self.image_oss_key,
            }]
            req.set_DiskDeviceMappings(dev_map)
            
            feature_map = {
                "NvmeSupport": "supported"
            }
            req.set_Features(feature_map)

            logger.info(f"dev: {dev_map}")
            response = parse_response(
                self.acs_client.do_action_with_exception(req))
            image_id = response.get("ImageId")
            logger.info(
                f"importing job {self.image_name}[{self.region}/{image_id}] is submitted. Waiting for processed"
            )
            self._wait_for_image(self.region, image_id)
            logger.info(
                f"finished importing image {self.image_name} in region {self.region}"
            )

        return image_id

    # tries to find all images with specified region and name.
    # If found, return the first found image_id
    def _check_image_existance(self, region, image_name) -> (bool, str):
        req = DescribeImagesRequest.DescribeImagesRequest()
        req.set_ImageName(image_name)
        req.set_Status(",".join(AlicloudImageStatus.to_availbel_str_array()))

        self.acs_client.set_region_id(region)
        response = parse_response(
            self.acs_client.do_action_with_exception(req))
        count = response.get("TotalCount")
        self.acs_client.set_region_id(self.region)

        if count == 0:
            return False, ""

        return True, response.get("Images").get("Image")[0].get("ImageId")

    ####
    def _wait_for_image(self, region, image_id):
        start_time = datetime.datetime.now()
        req = DescribeImagesRequest.DescribeImagesRequest()
        req.set_ImageId(image_id)
        req.set_Status(",".join(AlicloudImageStatus.to_availbel_str_array()))
        self.acs_client.set_region_id(region)
        while True:
            elapse = datetime.datetime.now() - start_time
            if elapse.seconds > TIME_OUT:
                raise Exception(f"Time out to wait image {image_id} be ready")
            response = parse_response(
                self.acs_client.do_action_with_exception(req))

            if response.get("Images").get("Image")[0].get("Status") == str(
                    AlicloudImageStatus.AVAILABLE):
                break

            sleep_seconds = 30
            logger.info(
                f"Image {image_id=} ({region=}) is not ready, will check it {sleep_seconds=} later"
            )
            time.sleep(sleep_seconds)

        self.acs_client.set_region_id(self.region)

    #####
    def _list_regions(self) -> []:
        req = DescribeRegionsRequest.DescribeRegionsRequest()
        response = parse_response(
            self.acs_client.do_action_with_exception(req))
        region_ids = []

        for region in response.get("Regions").get("Region"):
            region_id = region.get("RegionId")
            if region_id == self.region:
                continue

            # https://www.alibabacloud.com/help/en/cloud-migration-guide-for-beginners/latest/regions-and-zones
            # As of 2024-08-12: 'India (Mumbai) Closing Down (ap-south-1)'
            # Australia is also shut down
            if region_id in ['ap-south-1', 'ap-southeast-2']:
                continue

            if self.regions_to_copy_to is not None:
                if region_id in self.regions_to_copy_to:
                    region_ids.append(region_id)
            else:
                region_ids.append(region_id)

        return region_ids

    ####
    def copy_image(self, src_image_id: str, dest_region: str) -> str:
        exist, image_id = self._check_image_existance(dest_region,
                                                      self.image_name)
        if exist:
            logger.info(
                f"found {self.image_name=} already exists in {dest_region=}, {image_id=} skip copying"
            )
        else:
            req = CopyImageRequest.CopyImageRequest()
            req.set_DestinationDescription(self.image_name)
            req.set_DestinationImageName(self.image_name)
            req.set_ImageId(src_image_id)
            req.set_DestinationRegionId(dest_region)
            logger.info(
                f"start to copy {src_image_id=} to {dest_region=}")
            response = parse_response(
                self.acs_client.do_action_with_exception(req))
            image_id = response.get("ImageId")
            logger.info(
                f"copying {self.image_name=} in {dest_region=} is in process, waiting for success"
            )
        return image_id


def parse_response(response):
    return json.loads(response)


def _credentials(alicloud_cfg: str | model.alicloud.AlicloudConfig):
    if isinstance(alicloud_cfg, str):
        cfg_factory = ctx.cfg_factory()
        alicloud_cfg = cfg_factory.alicloud(alicloud_cfg)

    if not isinstance(alicloud_cfg, model.alicloud.AlicloudConfig):
        raise ValueError(f'alicloud_cfg must be of type "model.alicloud.AlicloudConfig"')

    return alicloud_cfg


def oss_auth(alicloud_cfg: str | model.alicloud.AlicloudConfig) -> oss2.Auth:
    alicloud_cfg = _credentials(alicloud_cfg)

    return oss2.Auth(
        access_key_id=alicloud_cfg.access_key_id(),
        access_key_secret=alicloud_cfg.access_key_secret(),
    )


def acs_client(alicloud_cfg: str | model.alicloud.AlicloudConfig) -> AcsClient:
    alicloud_cfg = _credentials(alicloud_cfg)

    return AcsClient(
        ak=alicloud_cfg.access_key_id(),
        secret=alicloud_cfg.access_key_secret(),
        region_id=alicloud_cfg.region(),
    )
