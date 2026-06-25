from app.mitre_rules import map_service_to_mitre, map_tool_to_mitre
from worker.mitre_mapper import map_to_mitre


def test_http_https_map_to_initial_access_t1190():
    assert map_service_to_mitre("http", 80).technique == "T1190"
    assert map_service_to_mitre("https", 443).phase == "Initial Access"


def test_directory_enumeration_maps_to_t1083():
    mapped = map_tool_to_mitre("dirb_safe")

    assert mapped.phase == "Discovery"
    assert mapped.technique == "T1083"


def test_ssh_maps_to_discovery_t1046():
    mapped = map_service_to_mitre("ssh", 22)
    worker_mapped = map_to_mitre({"evidence_type": "ssh_service"})

    assert mapped.phase == "Discovery"
    assert mapped.technique == "T1046"
    assert worker_mapped["tactic"] == "Discovery"
    assert worker_mapped["technique_id"] == "T1046"


def test_mysql_maps_to_collection():
    mapped = map_service_to_mitre("mysql", 3306)

    assert mapped.phase == "Collection"
    assert mapped.technique == "T1213"


def test_nuclei_does_not_map_to_generic_t1046():
    mapped = map_tool_to_mitre("nuclei_safe", "vulnerability")

    assert mapped.technique == "T1190"
    assert mapped.technique != "T1046"
