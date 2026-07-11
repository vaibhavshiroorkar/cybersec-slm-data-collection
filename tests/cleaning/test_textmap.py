from cybersec_slm.cleaning import textmap


def test_plain_text_passthrough():
    t, f = textmap.to_text({"text": "hello world"})
    assert t == "hello world"
    assert f == "text"


def test_question_answer_combo():
    t, f = textmap.to_text({"question": "What is XSS?", "answer": "Cross-site scripting"})
    assert "What is XSS?" in t and "Cross-site scripting" in t
    assert f == "question+answer"


def test_feature_table_row_excluded():
    # A pure feature/label row (no prose column) must be excluded.
    t, f = textmap.to_text({"url": "http://x", "label": 1, "length": 42})
    assert t is None and f is None


# ── chat shape (system/user/assistant) ───────────────────────────────────────

def test_chat_user_assistant_maps_without_system_boilerplate():
    rec = {
        "system": "You are a cybersecurity expert. " * 20,
        "user": "How does a buffer overflow work?",
        "assistant": "A buffer overflow writes past an allocated buffer...",
    }
    t, f = textmap.to_text(rec)
    assert t is not None
    assert "How does a buffer overflow work?" in t
    assert "A buffer overflow writes past" in t
    # The repeated system prompt is boilerplate — it must NOT be included, so
    # 100k records don't all share an identical multi-hundred-token prefix.
    assert "You are a cybersecurity expert" not in t


def test_chat_is_case_insensitive():
    # ALPHAzero1233 All-CVE uses capitalized System/User/Assistant.
    rec = {"System": "expert", "User": "Analyze CVE-2010-3763", "Assistant": "It is a SQLi..."}
    t, f = textmap.to_text(rec)
    assert t is not None
    assert "Analyze CVE-2010-3763" in t and "It is a SQLi" in t


# ── DPO shape (prompt/chosen/rejected) ───────────────────────────────────────

def test_dpo_uses_chosen_not_rejected():
    rec = {"prompt": "Write secure code", "chosen": "GOOD answer", "rejected": "BAD answer"}
    t, f = textmap.to_text(rec)
    assert t is not None
    assert "GOOD answer" in t
    assert "BAD answer" not in t


# ── ShareGPT / OpenAI messages list ──────────────────────────────────────────

def test_messages_list_openai():
    rec = {"messages": [
        {"role": "system", "content": "boilerplate system"},
        {"role": "user", "content": "Explain SQL injection"},
        {"role": "assistant", "content": "SQLi injects SQL via input"},
    ]}
    t, f = textmap.to_text(rec)
    assert t is not None
    assert "Explain SQL injection" in t and "SQLi injects SQL" in t
    assert "boilerplate system" not in t


def test_conversations_list_sharegpt():
    rec = {"conversations": [
        {"from": "human", "value": "What is CSRF?"},
        {"from": "gpt", "value": "Cross-site request forgery"},
    ]}
    t, f = textmap.to_text(rec)
    assert t is not None
    assert "What is CSRF?" in t and "Cross-site request forgery" in t


def test_empty_messages_excluded():
    assert textmap.to_text({"messages": []}) == (None, None)
    assert textmap.to_text({"conversations": [{"from": "system", "value": "x"}]}) == (None, None)
