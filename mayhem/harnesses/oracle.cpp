/*
 * oracle.cpp — self-contained golden oracle for DPP's Discord event-payload JSON parser.
 *
 * DPP's own unittest suite (src/unittest) needs a live DISCORD token + network, so it cannot
 * run offline. This oracle instead exercises the exact code path the fuzzer hits — parse a
 * Discord JSON payload then dpp::message::fill_from_json — over KNOWN-GOOD and KNOWN-BAD inputs,
 * and asserts the extracted fields byte-for-byte. It is a real PATCH-grade oracle: a no-op /
 * "return early" change to the message parser makes the field assertions fail.
 *
 * Each check prints "ok - <name>" or "not ok - <name>"; main returns the number of failures
 * (0 == all passed). mayhem/test.sh runs this and converts the tally to CTRF.
 */
#include <cstdio>
#include <string>

#include <dpp/json.h>
#include <dpp/message.h>
#include <dpp/user.h>

static int failures = 0;
static int total = 0;

static void check(const char *name, bool cond) {
	++total;
	if (cond) {
		std::printf("ok - %s\n", name);
	} else {
		std::printf("not ok - %s\n", name);
		++failures;
	}
}

/* A representative Discord MESSAGE_CREATE gateway payload (trimmed). */
static const char *kMessageJson = R"JSON({
  "id": "1107000000000000123",
  "channel_id": "999000000000000456",
  "guild_id": "888000000000000789",
  "content": "hello mayhem 😀",
  "type": 0,
  "tts": false,
  "pinned": true,
  "mention_everyone": false,
  "author": {
    "id": "555000000000000111",
    "username": "fuzzbot",
    "global_name": "Fuzz Bot",
    "discriminator": "0001"
  },
  "timestamp": "2024-01-02T03:04:05.000000+00:00",
  "embeds": [],
  "attachments": [],
  "mentions": [],
  "mention_roles": [],
  "components": []
})JSON";

int main() {
	/* 1) A well-formed message parses and yields the expected fields. */
	{
		dpp::json j = dpp::json::parse(kMessageJson, nullptr, false);
		check("known-good message JSON parses (not discarded)", !j.is_discarded());

		dpp::message m;
		bool threw = false;
		try {
			m.fill_from_json(&j, dpp::cache_policy::cpol_none);
		} catch (...) {
			threw = true;
		}
		check("message::fill_from_json does not throw on valid payload", !threw);

		check("message id parsed",     (uint64_t) m.id == 1107000000000000123ULL);
		check("channel_id parsed",     (uint64_t) m.channel_id == 999000000000000456ULL);
		check("guild_id parsed",       (uint64_t) m.guild_id == 888000000000000789ULL);
		check("content parsed",        m.content == "hello mayhem \xF0\x9F\x98\x80"); /* U+1F600 */
		check("type parsed (mt_default=0)", (int) m.type == 0);
		check("tts parsed (false)",    m.tts == false);
		check("pinned parsed (true)",  m.pinned == true);
		check("author id parsed",      (uint64_t) m.author.id == 555000000000000111ULL);
		check("author username parsed", m.author.username == "fuzzbot");
		check("author global_name parsed", m.author.global_name == "Fuzz Bot");
	}

	/* 2) A standalone user payload parses through json_interface<user>. */
	{
		const char *uj = R"JSON({"id":"42","username":"alice","global_name":"Alice"})JSON";
		dpp::json j = dpp::json::parse(uj, nullptr, false);
		check("known-good user JSON parses", !j.is_discarded());
		dpp::user u;
		u.fill_from_json(&j);
		check("user id parsed",       (uint64_t) u.id == 42ULL);
		check("user username parsed", u.username == "alice");
	}

	/* 3) Malformed JSON is REJECTED (discarded), never silently accepted — this is the
	 *    "reject malformed" half of the oracle and what the fuzzer's reject path relies on. */
	{
		const char *bad[] = {
			"{ this is not json",
			"{\"id\": }",
			"[1,2,",
			"\xff\xfe\x00garbage",
		};
		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
			dpp::json j = dpp::json::parse(bad[i], bad[i] + std::string(bad[i]).size(),
			                               nullptr, /*allow_exceptions*/ false);
			char nm[64];
			std::snprintf(nm, sizeof(nm), "malformed input #%zu is rejected", i);
			check(nm, j.is_discarded());
		}
	}

	std::printf("\n# %d/%d checks passed, %d failed\n", total - failures, total, failures);
	return failures;
}
