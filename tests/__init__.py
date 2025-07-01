from pytest import fixture

@fixture(autouse=True)
def run_around_tests():
    pass

def test_hello_world():
    assert True