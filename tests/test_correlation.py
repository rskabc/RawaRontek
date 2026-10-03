from rawarontek.intelligence.correlation import build_cve_candidates


def test_candidate_is_not_confirmed():
    results = {"Nmap Service Detection": "nginx 1.24.0"}
    candidates = build_cve_candidates(results)
    assert candidates
    assert candidates[0]["confidence"] == "POTENTIAL"
    assert candidates[0]["status"] == "REQUIRES_CPE_NVD_VALIDATION"
