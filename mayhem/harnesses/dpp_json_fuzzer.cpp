/*
 * dpp_json_fuzzer.cpp — fuzz D++ (DPP)'s Discord event-payload JSON parse path.
 *
 * Discord delivers gateway/REST data as JSON; DPP turns those payloads into C++
 * objects through the json_interface<T>::fill_from_json(nlohmann::json*) family
 * (and a few object constructors that take a json*). The attacker-controlled
 * surface is therefore: arbitrary bytes -> nlohmann::json::parse -> fill_from_json.
 *
 * This harness drives exactly that surface:
 *   1. Parse the raw input as JSON (DPP itself does json::parse on every gateway
 *      frame; malformed JSON is caught and rejected, which is in-scope behaviour).
 *   2. Feed the parsed value into several of DPP's richest event-object parsers:
 *        - dpp::message  (MESSAGE_CREATE / MESSAGE_UPDATE payloads — the deepest
 *          nested parser: author, members, mentions, embeds, components,
 *          attachments, reactions, stickers, reference, poll, ...)
 *        - dpp::user, dpp::guild, dpp::channel, dpp::embed
 *   message::fill_from_json is driven with cache_policy_t{cp_none,...} so NO
 *   cluster/shard is required and nothing is written to the global cache — the
 *   parse runs fully self-contained.
 *
 * The library is compiled WITH $SANITIZER_FLAGS (ASan+UBSan), so the parser code
 * — not just this harness — is instrumented.
 */
#include <cstdint>
#include <cstddef>
#include <string>

#include <dpp/json.h>
#include <dpp/message.h>
#include <dpp/user.h>
#include <dpp/guild.h>
#include <dpp/channel.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* DPP parses gateway frames with exceptions disabled (allow_exceptions=false)
	 * and a non-throwing error handler. Mirror that: a parse error returns a
	 * discarded value rather than throwing. */
	dpp::json j = dpp::json::parse(
		data, data + size,
		/* cb */ nullptr,
		/* allow_exceptions */ false,
		/* ignore_comments */ false);

	if (j.is_discarded()) {
		/* Malformed input — rejected, as the real client would. In-scope. */
		return 0;
	}

	/* Every fill_from_json below can still throw on type-mismatched-but-valid
	 * JSON (e.g. a field the parser does get_to<>()'s into the wrong type); DPP's
	 * dispatch layer swallows those. Contain them here so only memory-safety /
	 * UB faults (which ASan+UBSan turn into aborts) escape to the fuzzer. */
	try {
		dpp::message m;
		m.fill_from_json(&j, dpp::cache_policy::cpol_none);
		(void) m.get_url();
	} catch (...) {}

	try {
		dpp::user u;
		u.fill_from_json(&j);
	} catch (...) {}

	try {
		dpp::guild g;
		g.fill_from_json(&j);
	} catch (...) {}

	try {
		dpp::channel c;
		c.fill_from_json(&j);
	} catch (...) {}

	try {
		/* embed has a json* constructor (the message embed parse path). */
		dpp::embed e(&j);
		(void) e.type;
	} catch (...) {}

	return 0;
}
