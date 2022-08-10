from aws_iam_utils.util import extract_action_components


def test_extract_action_for_simple_action():
    input = "ec2:CreateImage"

    assert extract_action_components(input) == ("ec2", "Create", "Image")


def test_extract_action_for_capitalised_subject():
    input = "wafv2:ListIPSets"

    assert extract_action_components(input) == ("wafv2", "List", "IP", "Sets")


def test_extract_action_for_simple_action_in_lowercase():
    input = "ec2:createimage"

    assert extract_action_components(input) == ("ec2", "Create", "Image")


def test_extract_action_for_capitalised_subject_in_lowercase():
    input = "wafv2:listipsets"

    assert extract_action_components(input) == ("wafv2", "List", "IP", "Sets")


# def test_extract_action_for_pre_verb_1():
#    input = "ec2:AdminGetAssociation"  # ficticious
#
#    assert extract_action_components(input) == ("ec2", "AdminGet", "Association")
#
#
# def test_extract_action_for_pre_verb_2():
#    input = "s3:BatchGetObject"
#
#    assert extract_action_components(input) == ("s3", "BatchGet", "Object")


def test_extract_action_for_pre_verb_3():
    input = "es:ESHttpGet"

    assert extract_action_components(input) == ("es", "ESHttpGet")


# def test_extract_action_for_really_long_made_up_action():
#    input = "svc:DoMyRandomThingWithASingleAPIWafv2"
#
#    assert extract_action_components(input) == (
#        "svc",
#        "Do",
#        "MyRandomThingWithASingleAPIWafv2",
#    )
