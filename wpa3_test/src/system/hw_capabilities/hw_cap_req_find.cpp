#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "config/RunStatus.h"
#include "logger/error_log.h"
#include "logger/log.h"
#include "system/hw_capabilities.h"

namespace wpa3_tester {
using namespace std;
using namespace filesystem;

// ---------------------- BACKTRACKING ------------------------ Map of (RuleKey -> OptionKey)

static string hash_from(const ActorMap &assignment) {
	vector<string> mac_parts;
	for(const auto &[actor_name, hw]: assignment) {
		const auto &perm_mac = (*hw)[SK::permanent_mac];
		if(!perm_mac.has_value()) return {};
		mac_parts.push_back(actor_name + "=" + *perm_mac);
	}
	ranges::sort(mac_parts);
	ostringstream oss;
	oss << hex << hash<string>{}(join(mac_parts));
	return oss.str().substr(0, 8);
}

bool hw_capabilities::find_solution(const vector<string> &ruleKeys, const size_t ruleIdx, const ActorMap &rules,
	const vector<ActorPtr> &options, unordered_set<size_t> &usedOptions, ActorMap &currentAssignment,
	const vector<string> &disabled_tests_hash_filler) {
	if(ruleIdx == ruleKeys.size()) {
		//check if not disabled by list
		if(!disabled_tests_hash_filler.empty() &&
			ranges::contains(disabled_tests_hash_filler, hash_from(currentAssignment)))
			return false;
		return true;
	}

	const string &actor_name = ruleKeys[ruleIdx];
	const auto &ruleIt = rules.find(actor_name);
	if(ruleIt == rules.end()) throw config_err("Missing rule actor config for actor: {}", actor_name);

	const Actor_config &currentRuleReq = *ruleIt->second;

	for(size_t i = 0; i < options.size(); i++) {
		if(usedOptions.contains(i)) continue;
		if(!currentRuleReq.matches(*options[i])) continue;

		usedOptions.insert(i);
		currentAssignment.insert_or_assign(actor_name, options[i]);

		if(find_solution(
			   ruleKeys, ruleIdx + 1, rules, options, usedOptions, currentAssignment, disabled_tests_hash_filler))
			return true;

		usedOptions.erase(i);
		currentAssignment.erase(actor_name);
	}
	return false;
}

void hw_capabilities::find_all_solutions(const vector<string> &ruleKeys, const size_t ruleIdx, const ActorMap &rules,
	const vector<ActorPtr> &options, unordered_set<size_t> &usedOptions, ActorMap &current, vector<ActorMap> &results) {
	if(ruleIdx == ruleKeys.size()) {
		results.push_back(current);
		return;
	}
	const string &actor_name = ruleKeys[ruleIdx];
	const auto &ruleIt = rules.find(actor_name);
	if(ruleIt == rules.end()) throw config_err("Missing rule actor config for actor: " + actor_name);
	const Actor_config &req = *ruleIt->second;
	for(size_t i = 0; i < options.size(); i++) {
		if(usedOptions.contains(i)) continue;
		if(!req.matches(*options[i])) continue;
		usedOptions.insert(i);
		current.insert_or_assign(actor_name, options[i]);
		find_all_solutions(ruleKeys, ruleIdx + 1, rules, options, usedOptions, current, results);
		usedOptions.erase(i);
		current.erase(actor_name);
	}
}

vector<ActorMap> hw_capabilities::check_all_req_options(const ActorMap &rules, const vector<ActorPtr> &options) {
	vector<string> ruleKeys;
	for(const auto &key: rules | views::keys) ruleKeys.push_back(key);
	vector<ActorMap> results;
	ActorMap current;
	unordered_set<size_t> used;
	find_all_solutions(ruleKeys, 0, rules, options, used, current, results);
	return results;
}

//TODO test
string hw_capabilities::get_heuristic_err_msg(const ActorMap &rules, const vector<ActorPtr> &options) {
	if(options.size() < rules.size())
		return format("not enough interfaces: {} required, {} available", rules.size(), options.size());
	string msg;
	for(const auto &[actor_name, req_ptr]: rules) {
		const Actor_config &req = *req_ptr;
		if(ranges::any_of(options, [&](const auto &opt) { return req.matches(*opt); })) continue;
		for(const auto k: sk_keys()) {
			if(k == SK::actor_name || k == SK::channel || k == SK::netns) continue;
			const auto &r = req[k];
			if(!r) continue;
			set<string> possible;
			for(const auto &opt: options) {
				const auto &o = (*opt)[k];
				if(o) possible.insert(*o);
			}
			if(possible.empty() || possible.contains(*r)) continue;
			msg += format(
				"{0} {1} is required by {2}, possible {0}s {{{3}}}; ", sk_name(k), *r, actor_name, join(possible, ","));
		}
		for(const auto k: bk_keys()) {
			const auto &r = req[k];
			if(!r) continue;
			set<string> possible;
			for(const auto &opt: options) {
				const auto &o = (*opt)[k];
				if(o) possible.insert(*o ? "true" : "false");
			}
			const string req_val = *r ? "true" : "false";
			if(possible.contains(req_val)) continue;
			msg += format("{0} {1} is required by {2}, possible {0}s {{{3}}}; ",
				bk_name(k),
				req_val,
				actor_name,
				join(possible, ","));
		}
	}
	if(msg.empty()) {
		// Frequency conflict: N actors need the same value but fewer than N options provide it
		for(const auto k: sk_keys()) {
			if(k == SK::actor_name || k == SK::channel || k == SK::netns || k == SK::ip_addr) continue;
			map<string, vector<string>> demand;
			for(const auto &[name, req_ptr]: rules) {
				const auto &r = (*req_ptr)[k];
				if(r) demand[*r].push_back(name);
			}
			for(const auto &[val, actors]: demand) {
				auto supply = static_cast<size_t>(ranges::count_if(options, [&](const auto &opt) {
					const auto &o = (*opt)[k];
					return o && *o == val;
				}));
				if(actors.size() <= supply) continue;
				msg += format("{} '{}' needed by {} actors ({}) but only {} option(s) provide it; ",
					sk_name(k),
					val,
					actors.size(),
					join(actors, ", "),
					supply);
			}
		}
		for(const auto k: bk_keys()) {
			map<bool, vector<string>> demand;
			for(const auto &[name, req_ptr]: rules) {
				const auto &r = (*req_ptr)[k];
				if(r) demand[*r].push_back(name);
			}
			for(const auto &[val, actors]: demand) {
				auto supply = static_cast<size_t>(ranges::count_if(options, [&](const auto &opt) {
					const auto &o = (*opt)[k];
					return o && *o == val;
				}));
				if(actors.size() <= supply) continue;
				msg += format("{} '{}' needed by {} actors ({}) but only {} option(s) provide it; ",
					bk_name(k),
					val ? "true" : "false",
					actors.size(),
					join(actors, ", "),
					supply);
			}
		}
		if(msg.empty()) {
			// exclusive claim conflict: actor A needs only option X, actor B needs only option Y
			map<string, vector<size_t>> actor_matches;
			for(const auto &[name, req_ptr]: rules)
				for(size_t i = 0; i < options.size(); i++)
					if(req_ptr->matches(*options[i])) actor_matches[name].push_back(i);

			// for each singly-matched actor, record which key makes its match unique
			auto exclusive_reason = [&](const string &name, const size_t opt_idx) -> string {
				const Actor_config &req = *rules.at(name);
				const Actor_config &opt = *options[opt_idx];
				for(const auto k: sk_keys()) {
					const auto &r = req[k];
					if(!r) continue;
					const auto &o = opt[k];
					if(!o || *o != *r) continue;
					const auto cnt = ranges::count_if(options, [&](const auto &op) {
						const auto &v = (*op)[k]; return v && *v == *r;
					});
					if(cnt == 1) return format("{}={}", sk_name(k), *r);
				}
				for(const auto k: bk_keys()) {
					const auto &r = req[k];
					if(!r) continue;
					const auto &o = opt[k];
					if(!o || *o != *r) continue;
					const auto cnt = ranges::count_if(options, [&](const auto &op) {
						const auto &v = (*op)[k]; return v && *v == *r;
					});
					if(cnt == 1) return format("{}={}", bk_name(k), *r ? "true" : "false");
				}
				return "?";
			};

			unordered_map<size_t, string> claimed; // option index -> "actor(reason)"
			for(const auto &[name, idxs]: actor_matches)
				if(idxs.size() == 1)
					claimed[idxs[0]] = format("{}[{}]", name, exclusive_reason(name, idxs[0]));

			for(const auto &[name, idxs]: actor_matches) {
				if(idxs.size() == 1) continue;
				vector<string> blockers;
				size_t free_count = 0;
				for(const size_t i: idxs) {
					if(const auto it = claimed.find(i); it != claimed.end())
						blockers.push_back(
							format("{}(claimed by {})", (*options[i])[SK::iface].value_or("?"), it->second));
					else
						++free_count;
				}
				if(free_count == 0 && !blockers.empty()) {
					// also show unclaimed options that don't match this actor (explain why they're unusable)
					const Actor_config &req = *rules.at(name);
					vector<string> incompatible;
					for(size_t i = 0; i < options.size(); i++) {
						if(claimed.contains(i)) continue;
						if(req.matches(*options[i])) continue;
						// find first mismatching BK key to explain why
						string reason;
						for(const auto k: bk_keys()) {
							const auto &r = req[k];
							if(!r) continue;
							const auto &o = (*options[i])[k];
							if(o && *o != *r) { reason = format("{}={}", bk_name(k), *o ? "true" : "false"); break; }
						}
						incompatible.push_back(format("{}({})",
							(*options[i])[SK::iface].value_or("?"), reason.empty() ? "incompatible" : reason));
					}
					msg += format("{}: claimed=[{}], incompatible=[{}]; ",
						name, join(blockers, ", "),
						incompatible.empty() ? "none" : join(incompatible, ", "));
				}
			}
			if(msg.empty()) msg = "each actor individually matches some option; conflict is combinatorial";
		}
	}
	return msg;
}
}
