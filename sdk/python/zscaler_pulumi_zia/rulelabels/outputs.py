# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'RuleLabelsCreatedBy',
    'RuleLabelsLastModifiedBy',
    'GetRuleLabelsCreatedByResult',
    'GetRuleLabelsLastModifiedByResult',
]

@pulumi.output_type
class RuleLabelsCreatedBy(dict):
    def __init__(__self__, *,
                 extensions: Optional[Mapping[str, str]] = None,
                 id: Optional[int] = None,
                 name: Optional[str] = None):
        """
        :param str name: The name of the devices to be created.
        """
        if extensions is not None:
            pulumi.set(__self__, "extensions", extensions)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Optional[Mapping[str, str]]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name of the devices to be created.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class RuleLabelsLastModifiedBy(dict):
    def __init__(__self__, *,
                 extensions: Optional[Mapping[str, str]] = None,
                 id: Optional[int] = None,
                 name: Optional[str] = None):
        """
        :param str name: The name of the devices to be created.
        """
        if extensions is not None:
            pulumi.set(__self__, "extensions", extensions)
        if id is not None:
            pulumi.set(__self__, "id", id)
        if name is not None:
            pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Optional[Mapping[str, str]]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The name of the devices to be created.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetRuleLabelsCreatedByResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: The unique identifer for the device group.
        :param str name: The name of the rule label to be exported.
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The unique identifer for the device group.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the rule label to be exported.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetRuleLabelsLastModifiedByResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: The unique identifer for the device group.
        :param str name: The name of the rule label to be exported.
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        The unique identifer for the device group.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The name of the rule label to be exported.
        """
        return pulumi.get(self, "name")


