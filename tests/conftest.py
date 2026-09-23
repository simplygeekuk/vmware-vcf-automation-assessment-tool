"""Shared synthetic AssessmentData fixture: a small environment with one of
every problem the checks look for."""

import pytest

from vcf_automation_assessment_tool.models import AssessmentData


@pytest.fixture
def sample_data():
    data = AssessmentData()
    data.meta = {
        "url": "https://vra.example.test",
        "generated_at": "2026-08-05T09:00:00+00:00",
        "tool_version": "0.1.0-test",
        "identity": "sample-admin",
        "iaas_api_version": "2021-07-15",
        "platform_version": "8.14.1.33234",
        "projects_filter": [],
        "skipped_areas": [],
        # The replatforming assessment is opt-in on the CLI; the fixture keeps
        # it on so the full report surface stays exercised.
        "powershell_parser": True,
        "javascript_parser": True,
    }
    data.raw["infrastructure"] = {
        "cloud_accounts": [
            {
                "id": "ca1",
                "name": "vc-prod",
                "cloudAccountType": "vsphere",
                "enabledRegions": [{"id": "r1", "name": "DC1"}],
                "status": "OK",
                # site:dc1 lives ONLY here: account tags are inherited by the
                # account's computes, so the resource-context constraint on it
                # is satisfiable - but storage profiles never inherit, so the
                # storage-context constraint on the same tag is a TAG-001 hit.
                "tags": [{"key": "env", "value": "prod"}, {"key": "site", "value": "dc1"}],
            },
            # Unreachable account with no capability tags: INF-003 (not OK)
            # and INF-004 (untagged) both fire on it; vc-prod on neither.
            {
                "id": "ca2",
                "name": "vc-broken",
                "cloudAccountType": "vsphere",
                "enabledRegions": [],
                "status": "FAILED",
                "tags": [],
            },
        ],
        "zones": [
            {
                "id": "z1",
                "name": "prod-zone",
                "placementPolicy": "DEFAULT",
                "tags": [{"key": "env", "value": "prod"}],
                "tagsToMatch": [{"key": "cluster", "value": "gold"}],
            },
            {"id": "z2", "name": "empty-zone", "tags": [], "tagsToMatch": []},
        ],
        "zone_compute_counts": {"z1": 3, "z2": 0},
        "fabric_computes": [
            {"id": "fc1", "name": "cluster-01", "tags": [{"key": "cluster", "value": "gold"}]},
        ],
        "network_profiles": [
            {
                "id": "np1",
                "name": "prod-nets",
                "isolationType": "NONE",
                "tags": [{"key": "net", "value": "prod"}],
            },
        ],
        "fabric_networks": [],
        "network_ip_ranges": [
            {
                "id": "ipr1",
                "name": "prod-range",
                "ipVersion": "IPv4",
                "startIPAddress": "10.0.0.10",
                "endIPAddress": "10.0.0.250",
                "totalNumberOfIPs": 241,
                "numberOfAllocatedIPs": 200,
                "numberOfAvailableIPs": 41,
            },
            {
                "id": "ipr2",
                "name": "dev-range",
                "ipVersion": "IPv4",
                "startIPAddress": "10.0.1.10",
                "endIPAddress": "10.0.1.59",
                "totalNumberOfIPs": 50,
                "numberOfAllocatedIPs": 50,
                "numberOfAvailableIPs": 0,
            },
        ],
        "external_network_ip_ranges": [],
        "secrets": [
            {
                "id": "sec1",
                "name": "ad-join-password",
                "description": "",
                "orgScoped": True,
                "projectId": "",
                "projectName": "",
                "projectIds": [],
                "createdBy": "sample-admin",
                "updatedBy": "sample-admin",
                "createdAt": "2025-01-01T00:00:00Z",
                "updatedAt": "2025-06-01T00:00:00Z",
            },
            {
                "id": "sec2",
                "name": "legacy-api-key",
                "description": "",
                "orgScoped": False,
                "projectId": "p1",
                "projectName": "Platform",
                "projectIds": ["p1"],
                "createdBy": "sample-admin",
                "updatedBy": "",
                "createdAt": "2024-03-01T00:00:00Z",
                "updatedAt": "",
            },
        ],
        "storage_profiles": [
            {
                "id": "sp1",
                "name": "gold-storage",
                "defaultItem": True,
                "tags": [{"key": "storage", "value": "gold"}],
            },
        ],
        "regions": [
            {"id": "r1", "externalRegionId": "Datacenter:dc-1", "cloudAccountId": "ca1"},
        ],
        "flavor_profiles": [
            {
                "id": "fp1",
                "name": "flavors",
                "_links": {"region": {"href": "/iaas/api/regions/r1"}},
                "flavorMappings": {"mapping": {"small": {}, "large": {}}},
            },
            # Nameless profile in a region we could not collect - the live
            # shape that made the table unreadable; identity must come from
            # its own externalRegionId.
            {
                "id": "fp2",
                "_links": {"region": {"href": "/iaas/api/regions/r-gone"}},
                "externalRegionId": "northeurope",
                "flavorMappings": {"mapping": {"tiny": {}}},
            },
        ],
        "image_profiles": [
            {
                "id": "ip1",
                "name": "images",
                "_links": {"region": {"href": "/iaas/api/regions/r1"}},
                "imageMappings": {"mapping": {"ubuntu": {"id": "img1"}, "broken": {}}},
            },
        ],
        "tags": [],
        "integrations": [{"id": "int1", "name": "vro-embedded", "integrationType": "vro"}],
        "naming_profiles": [
            {
                "id": "naming-1",
                "name": "Platform machine names",
                "details_collected": True,
                "projects": [{"projectId": "p1", "projectName": "Platform", "active": True}],
                "templates": [
                    {
                        "resourceType": "COMPUTE",
                        "pattern": "srv-${resource.env}-${###}",
                        "startCounter": 1,
                        "incrementStep": 1,
                        "counters": [{"projectId": "p1", "currentCounter": 12, "active": True}],
                    }
                ],
            }
        ],
        "projects": [
            {
                "id": "p1",
                "name": "Platform",
                "machineNamingTemplate": "${project.name}-${###}",
                "administrators": [{"email": "admin@x"}],
                # alice owns deployments here and is named directly; the team
                # is a group, which the API never expands, so the owners it
                # covers read as having no direct grant.
                "members": [
                    {"email": "alice@x", "type": "user"},
                    {"email": "platform-team@x@x", "type": "group"},
                    {"email": "ghost-team@x@x", "type": "group"},
                ],
                "viewers": [],
                # A quota with room on one limit, none on another and no
                # limit at all on a third: the allocation table renders all
                # three cell shapes, and PRJ-004 fires on the full one.
                "zones": [
                    {
                        "zoneId": "z1",
                        "priority": 0,
                        "maxNumberInstances": 4,
                        "allocatedInstancesCount": 4,
                        "memoryLimitMB": 16384,
                        "allocatedMemoryMB": 12288,
                        "cpuLimit": 0,
                        "allocatedCpu": 6,
                        "storageLimitGB": 500,
                        "allocatedStorageGB": 210.5,
                    }
                ],
                "constraints": {},
            },
            {
                "id": "p2",
                "name": "EmptyProject",
                "administrators": [],
                "members": [],
                "viewers": [],
                "zones": [],
                "constraints": {},
            },
        ],
    }
    data.derived["project_names"] = {"p1": "Platform", "p2": "EmptyProject"}
    data.derived["capability_tags"] = {
        "env:prod": [
            {"kind": "cloud-zone", "id": "z1", "name": "prod-zone", "via": "capability tag"},
            {
                "kind": "cloud-account",
                "id": "ca1",
                "name": "vc-prod",
                "via": "inherited by its computes",
            },
        ],
        # Lives ONLY on the cloud account (inherited by its computes, never by
        # storage profiles) - satisfies the resource-context constraint, not
        # the storage-context one.
        "site:dc1": [
            {
                "kind": "cloud-account",
                "id": "ca1",
                "name": "vc-prod",
                "via": "inherited by its computes",
            }
        ],
        "cluster:gold": [
            {
                "kind": "cloud-zone",
                "id": "z1",
                "name": "prod-zone",
                "via": "compute filter (tagsToMatch)",
            },
            {"kind": "fabric-compute", "id": "fc1", "name": "cluster-01", "via": "capability tag"},
        ],
        "net:prod": [
            {"kind": "network-profile", "id": "np1", "name": "prod-nets", "via": "capability tag"}
        ],
        "storage:gold": [
            {
                "kind": "storage-profile",
                "id": "sp1",
                "name": "gold-storage",
                "via": "capability tag",
            }
        ],
        "orphan:tag": [
            {
                "kind": "storage-profile",
                "id": "sp1",
                "name": "gold-storage",
                "via": "capability tag",
            }
        ],
        # No static constraint references env:qa, but the web-server template
        # carries the dynamic constraint env:${input.env} which could select
        # it at request time - TAG-003 must NOT call it unreferenced (live
        # false positive: input-driven network selection).
        "env:qa": [
            {"kind": "cloud-zone", "id": "z2", "name": "empty-zone", "via": "capability tag"}
        ],
    }
    data.raw["deployments"] = {
        "deployments": [
            {
                "id": "d1",
                "name": "web-prod",
                "status": "CREATE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci1",
                "blueprintId": "bp1",
                "createdAt": "2025-01-01T00:00:00Z",
                "lastUpdatedAt": "2025-01-01T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "alice",
                "lastRequestStatus": "SUCCESSFUL",
                "resources": [
                    {
                        "id": "r1",
                        "name": "vm-1",
                        "type": "Cloud.vSphere.Machine",
                        "state": "OK",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                    },
                    # Second machine: makes web-prod a multi-machine stack
                    # (DEP-006). Disks/networks would not count.
                    {
                        "id": "r1b",
                        "name": "vm-2",
                        "type": "Cloud.vSphere.Machine",
                        "state": "OK",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                    },
                ],
            },
            {
                "id": "d2",
                "name": "failed-dep",
                "status": "CREATE_FAILED",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci1",
                "blueprintId": "bp1",
                "createdAt": "2025-06-01T00:00:00Z",
                "lastUpdatedAt": "2025-06-01T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "bob",
                "lastRequestStatus": "FAILED",
                "resources": [],
            },
            {
                "id": "d3",
                "name": "empty-dep",
                "status": "CREATE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": None,
                "blueprintId": None,
                "createdAt": "2025-02-01T00:00:00Z",
                "lastUpdatedAt": "2025-02-01T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "bob",
                "lastRequestStatus": "SUCCESSFUL",
                "resources": [
                    {
                        "id": "r2",
                        "name": "net-only",
                        "type": "Cloud.Network",
                        "state": "OK",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                    }
                ],
            },
            {
                "id": "d4",
                "name": "ghost-dep",
                "status": "CREATE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci-gone",
                "blueprintId": "bp-gone",
                "createdAt": "2025-03-01T00:00:00Z",
                "lastUpdatedAt": "2025-03-01T00:00:00Z",
                "leaseExpireAt": "2025-04-01T00:00:00Z",
                "ownedBy": "carol",
                "lastRequestStatus": "SUCCESSFUL",
                "resources": [
                    {
                        "id": "r3",
                        "name": "vm-ghost",
                        "type": "Cloud.vSphere.Machine",
                        "state": "OK",
                        "syncStatus": "MISSING",
                        "origin": "DEPLOYED",
                    }
                ],
            },
            # Created from a vRO workflow item: a machineless automation run,
            # which is what a workflow catalog item produces.
            {
                "id": "d6",
                "name": "workflow-run",
                "status": "CREATE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci3",
                "blueprintId": None,
                "createdAt": "2025-05-02T00:00:00Z",
                "lastUpdatedAt": "2025-05-02T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "bob",
                "lastRequestStatus": "SUCCESSFUL",
                "resources": [],
            },
            # Machineless by design: bp3 defines only a network resource.
            {
                "id": "d7",
                "name": "lb-net",
                "status": "CREATE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": None,
                "blueprintId": "bp3",
                "createdAt": "2025-05-03T00:00:00Z",
                "lastUpdatedAt": "2025-05-03T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "erin",
                "lastRequestStatus": "SUCCESSFUL",
                "resources": [
                    {
                        "id": "r4",
                        "name": "lb-segment",
                        "type": "Cloud.NSX.Network",
                        "state": "OK",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                    }
                ],
            },
            # Failed after its machines were built: DEP-010's case. One is
            # still running, and the other reports no power state at all, so
            # the finding has to show both without calling the second one off.
            {
                "id": "d8",
                "name": "half-built",
                "status": "CREATE_FAILED",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci1",
                "blueprintId": "bp1",
                "createdAt": "2025-06-10T00:00:00Z",
                "lastUpdatedAt": "2025-06-10T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "bob",
                "lastRequestStatus": "FAILED",
                "resources": [
                    {
                        "id": "r8a",
                        "name": "vm-half-1",
                        "type": "Cloud.vSphere.Machine",
                        "state": "OK",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                        "powerState": "ON",
                    },
                    {
                        "id": "r8b",
                        "name": "vm-half-2",
                        "type": "Cloud.vSphere.Machine",
                        "state": "PARTIAL",
                        "syncStatus": "SYNCED",
                        "origin": "DEPLOYED",
                    },
                ],
            },
            {
                "id": "d5",
                "name": "stuck-dep",
                "status": "CREATE_INPROGRESS",
                "projectId": "p1",
                "projectName": "Platform",
                "catalogItemId": "ci1",
                "blueprintId": "bp1",
                "createdAt": "2025-05-01T00:00:00Z",
                "lastUpdatedAt": "2025-05-01T00:00:00Z",
                "leaseExpireAt": None,
                "ownedBy": "dave",
                "lastRequestStatus": "INPROGRESS",
                "resources": [],
            },
        ],
        # Soft-deleted: history, never counted with the live estate. The
        # DELETE_FAILED one is what DEP-007 exists for - removed without ever
        # reaching a good state, so whatever it left behind is unrecorded.
        "deleted": [
            {
                "id": "d90",
                "name": "old-sandbox",
                "status": "DELETE_SUCCESSFUL",
                "projectId": "p1",
                "projectName": "Platform",
                "ownedBy": "bob",
                "createdAt": "2024-11-01T00:00:00Z",
                "lastUpdatedAt": "2025-04-02T00:00:00Z",
                "resources": [],
            },
            {
                "id": "d91",
                "name": "half-removed",
                "status": "DELETE_FAILED",
                "projectId": "p1",
                "projectName": "Platform",
                "ownedBy": "carol",
                "createdAt": "2024-12-01T00:00:00Z",
                "lastUpdatedAt": "2025-05-20T00:00:00Z",
                "resources": [],
            },
        ],
        "request_history": {
            "collected": True,
            "deployments_scanned": 9,
            "deployments_unread": 0,
            "oldest": "2024-11-01T09:00:00Z",
            "requests": [
                {
                    "id": "rq1",
                    "name": "Create",
                    "action_id": "",
                    "status": "SUCCESSFUL",
                    "requested_by": "alice",
                    "created_at": "2024-11-01T09:00:00Z",
                    "completed_at": "2024-11-01T09:12:00Z",
                    "total_tasks": 6,
                    "completed_tasks": 6,
                    "details": "",
                    "catalog_item_id": "ci1",
                    "blueprint_id": "bp1",
                    "deployment_id": "d1",
                    "deployment_name": "web-prod",
                    "project_name": "Platform",
                    "deployment_deleted": False,
                },
                {
                    "id": "rq2",
                    "name": "Power Off",
                    "action_id": "Deployment.PowerOff",
                    "status": "FAILED",
                    "requested_by": "bob",
                    "created_at": "2025-02-14T11:00:00Z",
                    "completed_at": "2025-02-14T11:03:00Z",
                    "total_tasks": 3,
                    "completed_tasks": 1,
                    "details": "host unreachable",
                    "catalog_item_id": "ci1",
                    "blueprint_id": "bp1",
                    "deployment_id": "d1",
                    "deployment_name": "web-prod",
                    "project_name": "Platform",
                    "deployment_deleted": False,
                },
                {
                    # A failure whose deployment is gone: exactly the history
                    # the live-status snapshot cannot show.
                    "id": "rq3",
                    "name": "Create",
                    "action_id": "",
                    "status": "FAILED",
                    "requested_by": "carol",
                    "created_at": "2025-05-19T08:00:00Z",
                    "completed_at": "2025-05-19T08:05:00Z",
                    "total_tasks": 6,
                    "completed_tasks": 2,
                    "details": "no capacity in zone",
                    "catalog_item_id": "ci1",
                    "blueprint_id": "bp1",
                    "deployment_id": "d91",
                    "deployment_name": "half-removed",
                    "project_name": "Platform",
                    "deployment_deleted": True,
                },
                {
                    # Cancelled by the requester: in neither half of the rate.
                    "id": "rq5",
                    "name": "Create",
                    "action_id": "",
                    "status": "ABORTED",
                    "requested_by": "erin",
                    "created_at": "2025-06-02T10:00:00Z",
                    "completed_at": "2025-06-02T10:01:00Z",
                    "total_tasks": 6,
                    "completed_tasks": 0,
                    "details": "",
                    "catalog_item_id": "ci1",
                    "blueprint_id": "bp1",
                    "deployment_id": "d1",
                    "deployment_name": "web-prod",
                    "project_name": "Platform",
                    "deployment_deleted": False,
                },
                {
                    # In flight, not a failure: counted apart from both.
                    "id": "rq4",
                    "name": "Change Lease",
                    "action_id": "Deployment.ChangeLease",
                    "status": "APPROVAL_PENDING",
                    "requested_by": "dave",
                    "created_at": "2025-06-01T10:00:00Z",
                    "completed_at": "",
                    "total_tasks": 4,
                    "completed_tasks": 0,
                    "details": "",
                    "catalog_item_id": "ci2",
                    "blueprint_id": "",
                    "deployment_id": "d4",
                    "deployment_name": "db-cluster",
                    "project_name": "Platform",
                    "deployment_deleted": False,
                },
            ],
        },
    }
    # Group expansion: platform-team resolves and covers bob, ghost-team is
    # not in the organization's list so its members are unknowable.
    data.raw["identity"] = {
        "collected": True,
        "org_group_count": 2,
        "groups": [
            {
                "principal": "platform-team@x@x",
                "id": "g1",
                "name": "platform-team@x",
                "domain": "x",
                "projects": ["p1"],
                "members": ["bob@x"],
                "members_read": True,
                "members_claimed": 1,
                "members_complete": True,
                "roles": ["org_member", "catalog:admin"],
                "elevated_roles": ["catalog:admin"],
            }
        ],
        "unresolved": [{"principal": "ghost-team@x@x", "projects": ["p1"]}],
    }
    data.raw["blueprints"] = {
        "blueprints": [
            {
                "id": "bp1",
                "name": "web-server",
                "projectId": "p1",
                "projectName": "Platform",
                "status": "RELEASED",
                "valid": True,
                "validationMessages": [],
                "totalVersions": 3,
                "totalReleasedVersions": 2,
                "contentSourceId": None,
                "parse_error": None,
                "secret_refs": ["ad-join-password"],
                "quality": {
                    "ips": ["192.168.10.5"],
                    "urls": [],
                    "secrets": [],
                    "inputs": 2,
                    "cloud_config_blocks": 1,
                    "cloud_config_lines": 12,
                },
                "resource_types": ["Cloud.vSphere.Machine"],
                "constraint_tags": [
                    {
                        "tag": "env:prod",
                        "hard": True,
                        "negated": False,
                        "dynamic": False,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "resource",
                    },
                    # Matched only by the vc-prod ACCOUNT tag: fine for the
                    # machine (computes inherit account tags) ...
                    {
                        "tag": "site:dc1",
                        "hard": True,
                        "negated": False,
                        "dynamic": False,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "resource",
                    },
                    # ... but a placement failure for storage, which does not
                    # inherit them (TAG-001 with the inheritance wording).
                    {
                        "tag": "site:dc1",
                        "hard": True,
                        "negated": False,
                        "dynamic": False,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "storage",
                    },
                    {
                        "tag": "no:such:tag",
                        "hard": True,
                        "negated": False,
                        "dynamic": False,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "resource",
                    },
                    {
                        "tag": "maybe:gone",
                        "hard": False,
                        "negated": False,
                        "dynamic": False,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "network[0]",
                    },
                    {
                        "tag": "env:${input.env}",
                        "hard": True,
                        "negated": False,
                        "dynamic": True,
                        "resource": "vm1",
                        "resource_type": "Cloud.vSphere.Machine",
                        "context": "resource",
                    },
                ],
            },
            # Network-only template, deployed as lb-net. Git-sourced, valid
            # and released so the hygiene checks pass it over.
            {
                "id": "bp3",
                "name": "lb-segment-only",
                "projectId": "p1",
                "projectName": "Platform",
                "status": "RELEASED",
                "valid": True,
                "validationMessages": [],
                "totalVersions": 1,
                "totalReleasedVersions": 1,
                "contentSourceId": "git-src-1",
                "parse_error": None,
                "quality": {
                    "ips": [],
                    "urls": [],
                    "secrets": [],
                    "inputs": 1,
                    "cloud_config_blocks": 0,
                    "cloud_config_lines": 0,
                },
                "resource_types": ["Cloud.NSX.Network"],
                "constraint_tags": [],
            },
            {
                "id": "bp2",
                "name": "draft-only",
                "projectId": "p1",
                "projectName": "Platform",
                "status": "DRAFT",
                "valid": False,
                "validationMessages": [{"message": "Unknown property 'flavorx'"}],
                "totalVersions": 1,
                "totalReleasedVersions": 0,
                "contentSourceId": "git-src-1",
                "parse_error": None,
                "quality": {
                    "ips": [],
                    "urls": [],
                    "secrets": [],
                    "inputs": 0,
                    "cloud_config_blocks": 0,
                    "cloud_config_lines": 0,
                },
                "resource_types": [],
                "constraint_tags": [],
            },
        ]
    }
    data.raw["catalog"] = {
        "admin_scope": True,
        "adhoc_deployment_count": 2,  # empty-dep and lb-net carry no catalogItemId
        "items": [
            {
                "id": "ci1",
                "name": "Web Server",
                "type": "com.vmw.blueprint",
                "sourceId": "src1",
                "sourceName": "Platform Templates",
                "projectIds": ["p1", "p2"],
                "custom_form": "enabled",
                "createdAt": "",
                "lastUpdatedAt": "",
                "deployment_count": 3,
                "deployment_success_count": 1,
                "deployment_failed_count": 1,
            },
            {
                "id": "ci2",
                "name": "Unused Item",
                "type": "com.vmw.blueprint",
                "sourceId": "src1",
                "sourceName": "Platform Templates",
                "projectIds": [],
                "custom_form": "",
                "createdAt": "",
                "lastUpdatedAt": "",
                "deployment_count": 0,
                "deployment_success_count": 0,
                "deployment_failed_count": 0,
            },
            {
                "id": "ci3",
                "name": "Reset VM Password",
                "type": "com.vmw.vro.workflow",
                "sourceId": "src1",
                "sourceName": "Platform Templates",
                "projectIds": ["p1"],
                "custom_form": "",
                "createdAt": "",
                "lastUpdatedAt": "",
                "deployment_count": 1,
                "deployment_success_count": 1,
                "deployment_failed_count": 0,
            },
        ],
        "sources": [
            {
                "id": "src1",
                "name": "Platform Templates",
                "typeId": "com.vmw.blueprint",
                "itemsImported": 2,
                "itemsFound": 3,
                "lastImportErrors": ["blueprint 'gone' not found"],
                "lastImportCompletedAt": "2026-07-01T10:00:00Z",
            },
        ],
    }
    data.raw["governance"] = {}
    data.raw["extensibility"] = {}
    data.raw["extensibility"]["subscriptions"] = [
        {
            "id": "sub1",
            "name": "add-to-cmdb",
            "description": "",
            "eventTopicId": "compute.provision.post",
            "blocking": True,
            "disabled": False,
            "priority": 10,
            "timeout": 0,
            "runnableType": "extensibility.abx",
            "runnableId": "abx1",
            "runnableName": "register-cmdb",
            "runnableResolved": True,
            "criteria": "",
            "scope": "global",
            "criteria_blueprint_ids": [],
            "criteria_project_ids": [],
            "constraints": {},
            "subscriberId": "",
            "system": False,
            "builtin": False,
        },
        {
            "id": "sub2",
            "name": "old-hook",
            "description": "",
            "eventTopicId": "deployment.request.pre",
            "blocking": False,
            "disabled": True,
            "priority": 10,
            "timeout": 0,
            "runnableType": "extensibility.abx",
            "runnableId": "abx-gone",
            "runnableName": "",
            "runnableResolved": False,
            "criteria": "event.data.blueprintId == 'bp-gone'",
            "scope": "blueprint",
            "criteria_blueprint_ids": ["bp-gone"],
            "criteria_project_ids": [],
            "constraints": {},
            "subscriberId": "",
            "system": False,
            "builtin": False,
        },
        {
            "id": "sub3",
            "name": "Quota enforcement",
            "description": "",
            "eventTopicId": "deployment.request.pre",
            "blocking": True,
            "disabled": False,
            "priority": 10,
            "timeout": 0,
            "runnableType": "extensibility.abx",
            "runnableId": "abx-sys",
            "runnableName": "",
            "runnableResolved": False,
            "criteria": "",
            "scope": "global",
            "criteria_blueprint_ids": [],
            "criteria_project_ids": [],
            "constraints": {},
            "subscriberId": "policy-service",
            "system": True,
            "builtin": True,
        },
        {
            # Disposal and day 2, so the sample report demonstrates every
            # concern section rather than only the two the build touches.
            "id": "sub4",
            "name": "release-addresses",
            "description": "",
            "eventTopicId": "compute.removal.post",
            "blocking": False,
            "disabled": False,
            "priority": 20,
            "timeout": 0,
            # ABX, not Orchestrator: a vRO runnable here would add an
            # "Orchestrator workflows" row to the capability map, which the
            # map's own test asserts this fixture does not have.
            "runnableType": "extensibility.abx",
            "runnableId": "abx1",
            "runnableName": "register-cmdb",
            "runnableResolved": True,
            "criteria": "",
            "scope": "global",
            "criteria_blueprint_ids": [],
            "criteria_project_ids": [],
            "constraints": {},
            "subscriberId": "",
            "system": False,
            "builtin": False,
        },
        {
            "id": "sub5",
            "name": "notify-on-resize",
            "description": "",
            "eventTopicId": "deployment.resource.action.post",
            "blocking": False,
            "disabled": False,
            "priority": 30,
            "timeout": 0,
            "runnableType": "extensibility.abx",
            "runnableId": "abx1",
            "runnableName": "register-cmdb",
            "runnableResolved": True,
            "criteria": "",
            "scope": "global",
            "criteria_blueprint_ids": [],
            "criteria_project_ids": [],
            "constraints": {},
            "subscriberId": "",
            "system": False,
            "builtin": False,
        },
    ]
    data.raw["governance"]["policies"] = [
        {
            "id": "pol1",
            "name": "prod-lease",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
        },
        {
            "id": "pol2",
            "name": "prod-approval",
            "typeId": "com.vmware.policy.approval",
            "enforcementType": "HARD",
        },
        # Per-project copies of one lease policy (identical definitions in
        # two projects) - the POL-001 consolidation candidate.
        {
            "id": "pol3",
            "name": "platform-lease",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
            "projectId": "p1",
            "definition": {"leaseTermMax": 30, "leaseGrace": 5},
        },
        {
            "id": "pol4",
            "name": "empty-lease",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
            "projectId": "p2",
            "definition": {"leaseGrace": 5, "leaseTermMax": 30},
        },
        # Different definition: legitimately project-specific, never flagged.
        {
            "id": "pol5",
            "name": "special-lease",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
            "projectId": "p1",
            "definition": {"leaseTermMax": 90},
        },
        # Identical twin of pol5 in the SAME project: not the org-scope
        # consolidation case, must stay unflagged.
        {
            "id": "pol6",
            "name": "special-lease-copy",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
            "projectId": "p1",
            "definition": {"leaseTermMax": 90},
        },
        # Content sharing policy: how current builds actually share the
        # catalog. Shares Web Server (ci1) with Platform - a grant Web
        # Server's projectIds already carries, so access patterns are
        # unchanged and the policy still exercises the parse + table.
        {
            "id": "pol7",
            "name": "share-platform-catalog",
            "typeId": "com.vmware.policy.catalog.entitlement",
            "enforcementType": "HARD",
            "projectId": "p1",
            "definition": {
                "entitledUsers": [
                    {
                        "userType": "USER",
                        "principals": [{"type": "PROJECT", "referenceId": ""}],
                        "items": [{"id": "ci1", "type": "CATALOG_ITEM_IDENTIFIER"}],
                    }
                ]
            },
        },
        # Scoped to a project that no longer exists (live lesson: policies
        # outlive their project's deletion) - the POL-002 case. A lease
        # policy so it cannot disturb the catalog access patterns.
        {
            "id": "pol8",
            "name": "orphaned-lease",
            "typeId": "com.vmware.policy.deployment.lease",
            "enforcementType": "HARD",
            "projectId": "p-deleted",
        },
    ]
    data.raw["governance"]["approval_policies"] = [
        {
            "id": "pol2",
            "name": "prod-approval",
            "enforcementType": "HARD",
            "projectId": "p1",
            "scopeCriteria": {},
            "level": 1,
            "approvalMode": "ANY_OF",
            "approverType": "USER",
            "approvers": ["USER:manager@x"],
            "autoApprovalDecision": "REJECT",
            "autoApprovalExpiry": 7,
            "actions": ["Deployment.Create"],
        }
    ]
    data.raw["governance"]["approval_requests"] = [
        {
            "id": "apr1",
            "status": "PENDING",
            "requestedBy": "bob",
            "createdAt": "2026-07-20T09:00:00Z",
            "deploymentName": "big-vm",
            "policyName": "prod-approval",
            "actionName": "Deployment.Create",
            "approvers": ["manager@x"],
        },
        {
            "id": "apr2",
            "status": "APPROVED",
            "requestedBy": "alice",
            "createdAt": "2026-06-01T09:00:00Z",
            "deploymentName": "web-prod",
            "policyName": "prod-approval",
            "actionName": "Deployment.Create",
            "approvers": ["manager@x"],
        },
    ]
    data.raw["extensibility"]["abx_actions"] = [
        {
            "id": "abx1",
            "name": "register-cmdb",
            "runtime": "python",
            "projectId": "p1",
            "selfLink": "/abx/abx1",
            "has_inline_source": True,
            "dependencies": "requests==2.31.0",
            "analysis": {
                "parses": True,
                "lines": 40,
                "functions": 2,
                "has_error_handling": True,
                "bare_excepts": 0,
                "swallowed_excepts": 0,
                "uses_logging": True,
                "print_calls": 0,
                "literals": {"ips": [], "urls": [], "secrets": []},
                "unpinned_dependencies": [],
            },
            "issues": [],
            "complexity": "LOW",
        },
        {
            "id": "abx2",
            "name": "legacy-dns-update",
            "runtime": "python",
            "projectId": "p1",
            "selfLink": "/abx/abx2",
            "has_inline_source": True,
            "dependencies": "dnspython",
            "analysis": {
                "parses": True,
                "lines": 25,
                "functions": 1,
                "has_error_handling": False,
                "bare_excepts": 0,
                "swallowed_excepts": 0,
                "uses_logging": False,
                "print_calls": 3,
                "literals": {
                    "ips": ["10.0.0.53"],
                    "urls": [],
                    "secrets": ["password"],
                },
                "unpinned_dependencies": ["dnspython"],
            },
            "issues": [
                "credential-looking literal(s): password",
                "hardcoded IP(s): 10.0.0.53",
                "unpinned dependencies: dnspython",
            ],
            "complexity": "LOW",
        },
        # Clean code but grown into an application - the EXT-004 case
        # (an ABX action should stay a short glue script).
        {
            "id": "abx3",
            "name": "vm-lifecycle-orchestrator",
            "runtime": "python",
            "projectId": "p1",
            "selfLink": "/abx/abx3",
            "has_inline_source": True,
            "dependencies": "requests==2.31.0",
            "analysis": {
                "parses": True,
                "lines": 320,
                "code_lines": 260,
                "comment_lines": 60,
                "comment_ratio": 0.19,
                "functions": 12,
                "branches": 44,
                "has_error_handling": True,
                "bare_excepts": 0,
                "swallowed_excepts": 0,
                "uses_logging": True,
                "print_calls": 0,
                "literals": {"ips": [], "urls": [], "secrets": []},
                "unpinned_dependencies": [],
            },
            "issues": [],
            "complexity": "HIGH",
        },
    ]
    # Retained run history read to completion: register-cmdb has run,
    # legacy-dns-update and vm-lifecycle-orchestrator have not (EXT-006).
    data.raw["extensibility"]["abx_run_evidence"] = {
        "collected": True,
        "complete": True,
        "total_runs": 3,
        # Oldest record still retained anywhere: 2025-07-01 - the floor
        # of the window the never-run claims cover.
        "oldest_run_millis": 1751328000000,
        "by_action": {
            "abx1": {"count": 3, "last_millis": 1784160000000, "last_state": "COMPLETED"}
        },
    }
    # Design-time content collected by the blueprint collector.
    data.raw["blueprints"]["custom_resource_types"] = []
    data.raw["blueprints"]["custom_resource_actions"] = []
    data.raw["blueprints"]["property_groups"] = [
        {"id": "pg1", "name": "common-props", "type": "CONSTANT", "properties": {"dns": {}}}
    ]
    data.raw["vro"] = {
        "endpoints": [
            {
                "url": "https://vra.example.test/vco",
                "source": "embedded",
                "reachable": True,
                "workflows_total": 812,
            }
        ],
        "workflows": [
            {
                "id": "wf-ad",
                "name": "Active Directory - Add Computer",
                "resolved": True,
                "endpoint_source": "embedded",
                "used_by": ["subscription: add-to-cmdb"],
                "structure": {
                    "items": 24,
                    "scriptable_tasks": 6,
                    "decisions": 6,
                    "sub_workflows": 4,
                    "user_interactions": 1,
                    "timers": 0,
                },
                "complexity": "HIGH",
            },
            {
                "id": "wf-legacy",
                "name": "wf-legacy",
                "resolved": False,
                "endpoint_source": "",
                "used_by": ["subscription: old-hook"],
                "structure": None,
                "complexity": "",
            },
        ],
        "actions": [
            {
                "id": "vro-a1",
                "fqn": "com.simplygeek.ad/addComputer",
                "name": "addComputer",
                "endpoint_source": "embedded",
                "runtime": "python",
                "lines": 30,
                "analysis": {"has_error_handling": True},
                "issues": [],
            },
            {
                "id": "vro-a2",
                "fqn": "com.simplygeek.dns/legacySetRecord",
                "name": "legacySetRecord",
                "endpoint_source": "embedded",
                "runtime": "javascript",
                "lines": 12,
                "analysis": {"has_error_handling": False},
                "issues": [
                    "hardcoded IP(s): 10.0.0.53",
                ],
            },
        ],
        "builtin_actions_excluded": 240,
        "action_runtimes": {"python": 1, "javascript": 1},
    }
    data.derived["vro_workflow_names"] = {"wf-ad": "Active Directory - Add Computer"}
    return data
