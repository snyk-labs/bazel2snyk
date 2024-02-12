from typer.testing import CliRunner
from bazel2snyk.cli import cli
from bazel2snyk.test.fixtures import pip_args

runner = CliRunner()


def test_bad_args():
    """
    Test for invalid argument set

    """
    result = runner.invoke(cli, pip_args["bad_args"])
    assert result.exit_code == 2


def test_pip_command_print_graph():
    """
    Test for printing the dep graph
    """
    result = runner.invoke(cli, pip_args["print_graph"])
    assert result.exit_code == 0


def test_pip_command_test():
    """
    Test for testing the dep graph
    """
    result = runner.invoke(cli, pip_args["test"])
    assert result.exit_code == 1


def test_pip_command_monitor():
    """
    Test for monitoring the dep graph in snyk
    """
    result = runner.invoke(cli, pip_args["monitor"])
    assert result.exit_code == 0


def test_maven_command_print_graph():
    """
    Test for printing the dep graph
    """
    result = runner.invoke(cli, pip_args["print_graph"])
    assert result.exit_code == 0


def test_maven_command_test():
    """
    Test for testing the dep graph
    """
    result = runner.invoke(cli, pip_args["test"])
    assert result.exit_code == 1


def test_maven_command_monitor():
    """
    Test for monitoring the dep graph in snyk
    """
    result = runner.invoke(cli, pip_args["monitor"])
    assert result.exit_code == 0
