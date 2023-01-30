# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'DLPDictionariesExactDataMatchDetail',
    'DLPDictionariesIdmProfileMatchAccuracy',
    'DLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile',
    'DLPDictionariesPattern',
    'DLPDictionariesPhrase',
    'DLPWebRulesAuditor',
    'DLPWebRulesDepartments',
    'DLPWebRulesDlpEngines',
    'DLPWebRulesExcludedDepartments',
    'DLPWebRulesExcludedGroups',
    'DLPWebRulesExcludedUsers',
    'DLPWebRulesGroups',
    'DLPWebRulesIcapServer',
    'DLPWebRulesLabels',
    'DLPWebRulesLocationGroups',
    'DLPWebRulesLocations',
    'DLPWebRulesNotificationTemplate',
    'DLPWebRulesTimeWindows',
    'DLPWebRulesUrlCategories',
    'DLPWebRulesUsers',
    'GetDLPDictionariesExactDataMatchDetailResult',
    'GetDLPDictionariesIdmProfileMatchAccuracyResult',
    'GetDLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileResult',
    'GetDLPDictionariesPatternResult',
    'GetDLPDictionariesPhraseResult',
    'GetDLPWebRulesAuditorResult',
    'GetDLPWebRulesDepartmentResult',
    'GetDLPWebRulesDlpEngineResult',
    'GetDLPWebRulesExcludedDepartmentResult',
    'GetDLPWebRulesExcludedGroupResult',
    'GetDLPWebRulesExcludedUserResult',
    'GetDLPWebRulesGroupResult',
    'GetDLPWebRulesIcapServerResult',
    'GetDLPWebRulesLabelResult',
    'GetDLPWebRulesLastModifiedByResult',
    'GetDLPWebRulesLocationResult',
    'GetDLPWebRulesLocationGroupResult',
    'GetDLPWebRulesNotificationTemplateResult',
    'GetDLPWebRulesTimeWindowResult',
    'GetDLPWebRulesUrlCategoryResult',
    'GetDLPWebRulesUserResult',
]

@pulumi.output_type
class DLPDictionariesExactDataMatchDetail(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "dictionaryEdmMappingId":
            suggest = "dictionary_edm_mapping_id"
        elif key == "primaryField":
            suggest = "primary_field"
        elif key == "schemaId":
            suggest = "schema_id"
        elif key == "secondaryFieldMatchOn":
            suggest = "secondary_field_match_on"
        elif key == "secondaryFields":
            suggest = "secondary_fields"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in DLPDictionariesExactDataMatchDetail. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        DLPDictionariesExactDataMatchDetail.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        DLPDictionariesExactDataMatchDetail.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 dictionary_edm_mapping_id: Optional[int] = None,
                 primary_field: Optional[int] = None,
                 schema_id: Optional[int] = None,
                 secondary_field_match_on: Optional[str] = None,
                 secondary_fields: Optional[Sequence[int]] = None):
        """
        :param int dictionary_edm_mapping_id: The unique identifier for the EDM mapping.
        :param int primary_field: The EDM template's primary field.
        :param int schema_id: The unique identifier for the EDM template (or schema).
        :param str secondary_field_match_on: The EDM secondary field to match on.
               - `"MATCHON_NONE"`
               - `"MATCHON_ANY_1"`
               - `"MATCHON_ANY_2"`
               - `"MATCHON_ANY_3"`
               - `"MATCHON_ANY_4"`
               - `"MATCHON_ANY_5"`
               - `"MATCHON_ANY_6"`
               - `"MATCHON_ANY_7"`
               - `"MATCHON_ANY_8"`
               - `"MATCHON_ANY_9"`
               - `"MATCHON_ANY_10"`
               - `"MATCHON_ANY_11"`
               - `"MATCHON_ANY_12"`
               - `"MATCHON_ANY_13"`
               - `"MATCHON_ANY_14"`
               - `"MATCHON_ANY_15"`
               - `"MATCHON_ALL"`
        :param Sequence[int] secondary_fields: The EDM template's secondary fields.
        """
        if dictionary_edm_mapping_id is not None:
            pulumi.set(__self__, "dictionary_edm_mapping_id", dictionary_edm_mapping_id)
        if primary_field is not None:
            pulumi.set(__self__, "primary_field", primary_field)
        if schema_id is not None:
            pulumi.set(__self__, "schema_id", schema_id)
        if secondary_field_match_on is not None:
            pulumi.set(__self__, "secondary_field_match_on", secondary_field_match_on)
        if secondary_fields is not None:
            pulumi.set(__self__, "secondary_fields", secondary_fields)

    @property
    @pulumi.getter(name="dictionaryEdmMappingId")
    def dictionary_edm_mapping_id(self) -> Optional[int]:
        """
        The unique identifier for the EDM mapping.
        """
        return pulumi.get(self, "dictionary_edm_mapping_id")

    @property
    @pulumi.getter(name="primaryField")
    def primary_field(self) -> Optional[int]:
        """
        The EDM template's primary field.
        """
        return pulumi.get(self, "primary_field")

    @property
    @pulumi.getter(name="schemaId")
    def schema_id(self) -> Optional[int]:
        """
        The unique identifier for the EDM template (or schema).
        """
        return pulumi.get(self, "schema_id")

    @property
    @pulumi.getter(name="secondaryFieldMatchOn")
    def secondary_field_match_on(self) -> Optional[str]:
        """
        The EDM secondary field to match on.
        - `"MATCHON_NONE"`
        - `"MATCHON_ANY_1"`
        - `"MATCHON_ANY_2"`
        - `"MATCHON_ANY_3"`
        - `"MATCHON_ANY_4"`
        - `"MATCHON_ANY_5"`
        - `"MATCHON_ANY_6"`
        - `"MATCHON_ANY_7"`
        - `"MATCHON_ANY_8"`
        - `"MATCHON_ANY_9"`
        - `"MATCHON_ANY_10"`
        - `"MATCHON_ANY_11"`
        - `"MATCHON_ANY_12"`
        - `"MATCHON_ANY_13"`
        - `"MATCHON_ANY_14"`
        - `"MATCHON_ANY_15"`
        - `"MATCHON_ALL"`
        """
        return pulumi.get(self, "secondary_field_match_on")

    @property
    @pulumi.getter(name="secondaryFields")
    def secondary_fields(self) -> Optional[Sequence[int]]:
        """
        The EDM template's secondary fields.
        """
        return pulumi.get(self, "secondary_fields")


@pulumi.output_type
class DLPDictionariesIdmProfileMatchAccuracy(dict):
    @staticmethod
    def __key_warning(key: str):
        suggest = None
        if key == "adpIdmProfile":
            suggest = "adp_idm_profile"
        elif key == "matchAccuracy":
            suggest = "match_accuracy"

        if suggest:
            pulumi.log.warn(f"Key '{key}' not found in DLPDictionariesIdmProfileMatchAccuracy. Access the value via the '{suggest}' property getter instead.")

    def __getitem__(self, key: str) -> Any:
        DLPDictionariesIdmProfileMatchAccuracy.__key_warning(key)
        return super().__getitem__(key)

    def get(self, key: str, default = None) -> Any:
        DLPDictionariesIdmProfileMatchAccuracy.__key_warning(key)
        return super().get(key, default)

    def __init__(__self__, *,
                 adp_idm_profile: Optional['outputs.DLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile'] = None,
                 match_accuracy: Optional[str] = None):
        """
        :param 'DLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileArgs' adp_idm_profile: The IDM template reference.
        :param str match_accuracy: The IDM template match accuracy.
               - `"LOW"`
               - `"MEDIUM"`
               - `"HEAVY"`
        """
        if adp_idm_profile is not None:
            pulumi.set(__self__, "adp_idm_profile", adp_idm_profile)
        if match_accuracy is not None:
            pulumi.set(__self__, "match_accuracy", match_accuracy)

    @property
    @pulumi.getter(name="adpIdmProfile")
    def adp_idm_profile(self) -> Optional['outputs.DLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile']:
        """
        The IDM template reference.
        """
        return pulumi.get(self, "adp_idm_profile")

    @property
    @pulumi.getter(name="matchAccuracy")
    def match_accuracy(self) -> Optional[str]:
        """
        The IDM template match accuracy.
        - `"LOW"`
        - `"MEDIUM"`
        - `"HEAVY"`
        """
        return pulumi.get(self, "match_accuracy")


@pulumi.output_type
class DLPDictionariesIdmProfileMatchAccuracyAdpIdmProfile(dict):
    def __init__(__self__, *,
                 extensions: Optional[Mapping[str, str]] = None,
                 id: Optional[int] = None):
        if extensions is not None:
            pulumi.set(__self__, "extensions", extensions)
        if id is not None:
            pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def extensions(self) -> Optional[Mapping[str, str]]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> Optional[int]:
        return pulumi.get(self, "id")


@pulumi.output_type
class DLPDictionariesPattern(dict):
    def __init__(__self__, *,
                 action: Optional[str] = None,
                 pattern: Optional[str] = None):
        """
        :param str action: The action applied to a DLP dictionary using patterns. The following values are supported:
        :param str pattern: DLP dictionary pattern
        """
        if action is not None:
            pulumi.set(__self__, "action", action)
        if pattern is not None:
            pulumi.set(__self__, "pattern", pattern)

    @property
    @pulumi.getter
    def action(self) -> Optional[str]:
        """
        The action applied to a DLP dictionary using patterns. The following values are supported:
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter
    def pattern(self) -> Optional[str]:
        """
        DLP dictionary pattern
        """
        return pulumi.get(self, "pattern")


@pulumi.output_type
class DLPDictionariesPhrase(dict):
    def __init__(__self__, *,
                 action: Optional[str] = None,
                 phrase: Optional[str] = None):
        """
        :param str action: The action applied to a DLP dictionary using patterns. The following values are supported:
        :param str phrase: DLP dictionary phrase
        """
        if action is not None:
            pulumi.set(__self__, "action", action)
        if phrase is not None:
            pulumi.set(__self__, "phrase", phrase)

    @property
    @pulumi.getter
    def action(self) -> Optional[str]:
        """
        The action applied to a DLP dictionary using patterns. The following values are supported:
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter
    def phrase(self) -> Optional[str]:
        """
        DLP dictionary phrase
        """
        return pulumi.get(self, "phrase")


@pulumi.output_type
class DLPWebRulesAuditor(dict):
    def __init__(__self__, *,
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class DLPWebRulesDepartments(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesDlpEngines(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesExcludedDepartments(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesExcludedGroups(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesExcludedUsers(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesGroups(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesIcapServer(dict):
    def __init__(__self__, *,
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class DLPWebRulesLabels(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesLocationGroups(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesLocations(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesNotificationTemplate(dict):
    def __init__(__self__, *,
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class DLPWebRulesTimeWindows(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesUrlCategories(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class DLPWebRulesUsers(dict):
    def __init__(__self__, *,
                 ids: Sequence[int]):
        """
        :param Sequence[int] ids: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "ids", ids)

    @property
    @pulumi.getter
    def ids(self) -> Sequence[int]:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "ids")


@pulumi.output_type
class GetDLPDictionariesExactDataMatchDetailResult(dict):
    def __init__(__self__, *,
                 dictionary_edm_mapping_id: int,
                 primary_field: int,
                 schema_id: int,
                 secondary_field_match_on: str,
                 secondary_fields: Sequence[int]):
        pulumi.set(__self__, "dictionary_edm_mapping_id", dictionary_edm_mapping_id)
        pulumi.set(__self__, "primary_field", primary_field)
        pulumi.set(__self__, "schema_id", schema_id)
        pulumi.set(__self__, "secondary_field_match_on", secondary_field_match_on)
        pulumi.set(__self__, "secondary_fields", secondary_fields)

    @property
    @pulumi.getter(name="dictionaryEdmMappingId")
    def dictionary_edm_mapping_id(self) -> int:
        return pulumi.get(self, "dictionary_edm_mapping_id")

    @property
    @pulumi.getter(name="primaryField")
    def primary_field(self) -> int:
        return pulumi.get(self, "primary_field")

    @property
    @pulumi.getter(name="schemaId")
    def schema_id(self) -> int:
        return pulumi.get(self, "schema_id")

    @property
    @pulumi.getter(name="secondaryFieldMatchOn")
    def secondary_field_match_on(self) -> str:
        return pulumi.get(self, "secondary_field_match_on")

    @property
    @pulumi.getter(name="secondaryFields")
    def secondary_fields(self) -> Sequence[int]:
        return pulumi.get(self, "secondary_fields")


@pulumi.output_type
class GetDLPDictionariesIdmProfileMatchAccuracyResult(dict):
    def __init__(__self__, *,
                 adp_idm_profiles: Sequence['outputs.GetDLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileResult'],
                 match_accuracy: str):
        pulumi.set(__self__, "adp_idm_profiles", adp_idm_profiles)
        pulumi.set(__self__, "match_accuracy", match_accuracy)

    @property
    @pulumi.getter(name="adpIdmProfiles")
    def adp_idm_profiles(self) -> Sequence['outputs.GetDLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileResult']:
        return pulumi.get(self, "adp_idm_profiles")

    @property
    @pulumi.getter(name="matchAccuracy")
    def match_accuracy(self) -> str:
        return pulumi.get(self, "match_accuracy")


@pulumi.output_type
class GetDLPDictionariesIdmProfileMatchAccuracyAdpIdmProfileResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int):
        """
        :param int id: Unique identifier for the DLP dictionary
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Unique identifier for the DLP dictionary
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class GetDLPDictionariesPatternResult(dict):
    def __init__(__self__, *,
                 action: str,
                 pattern: str):
        """
        :param str action: (String) The action applied to a DLP dictionary using patterns
        :param str pattern: (String) DLP dictionary pattern
        """
        pulumi.set(__self__, "action", action)
        pulumi.set(__self__, "pattern", pattern)

    @property
    @pulumi.getter
    def action(self) -> str:
        """
        (String) The action applied to a DLP dictionary using patterns
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter
    def pattern(self) -> str:
        """
        (String) DLP dictionary pattern
        """
        return pulumi.get(self, "pattern")


@pulumi.output_type
class GetDLPDictionariesPhraseResult(dict):
    def __init__(__self__, *,
                 action: str,
                 phrase: str):
        """
        :param str action: (String) The action applied to a DLP dictionary using patterns
        """
        pulumi.set(__self__, "action", action)
        pulumi.set(__self__, "phrase", phrase)

    @property
    @pulumi.getter
    def action(self) -> str:
        """
        (String) The action applied to a DLP dictionary using patterns
        """
        return pulumi.get(self, "action")

    @property
    @pulumi.getter
    def phrase(self) -> str:
        return pulumi.get(self, "phrase")


@pulumi.output_type
class GetDLPWebRulesAuditorResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesDepartmentResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesDlpEngineResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesExcludedDepartmentResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class GetDLPWebRulesExcludedGroupResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class GetDLPWebRulesExcludedUserResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int):
        """
        :param int id: Identifier that uniquely identifies an entity
        """
        pulumi.set(__self__, "extensions", extensions)
        pulumi.set(__self__, "id", id)

    @property
    @pulumi.getter
    def extensions(self) -> Mapping[str, str]:
        return pulumi.get(self, "extensions")

    @property
    @pulumi.getter
    def id(self) -> int:
        """
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")


@pulumi.output_type
class GetDLPWebRulesGroupResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesIcapServerResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesLabelResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesLastModifiedByResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesLocationResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesLocationGroupResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesNotificationTemplateResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesTimeWindowResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesUrlCategoryResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")


@pulumi.output_type
class GetDLPWebRulesUserResult(dict):
    def __init__(__self__, *,
                 extensions: Mapping[str, str],
                 id: int,
                 name: str):
        """
        :param int id: Identifier that uniquely identifies an entity
        :param str name: The DLP policy rule name.
               rules.
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
        Identifier that uniquely identifies an entity
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The DLP policy rule name.
        rules.
        """
        return pulumi.get(self, "name")

