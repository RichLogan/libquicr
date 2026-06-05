// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct Subscribe
    {
        static constexpr std::uint64_t kType = 0x3;

        const RequestID request_id;
        const TrackNamespace track_namespace;
        const TrackName track_name;
        const std::vector<Token> auth_tokens;
        const std::optional<std::uint64_t> object_delivery_timeout;
        const std::optional<std::uint64_t> subgroup_delivery_timeout;
        const std::uint64_t rendezvous_timeout;
        const std::uint8_t subscriber_priority;
        const std::optional<GroupOrder> group_order;
        const Filter subscription_filter;
        const bool forward;
        const std::optional<std::uint64_t> new_group_request;

        explicit Subscribe(BytesSpan payload)
          : Subscribe(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            TrackNamespace track_namespace;
            TrackName track_name;
            std::vector<Token> auth_tokens;
            std::optional<std::uint64_t> object_delivery_timeout;
            std::optional<std::uint64_t> subgroup_delivery_timeout;
            std::uint64_t rendezvous_timeout;
            std::uint8_t subscriber_priority;
            std::optional<GroupOrder> group_order;
            Filter subscription_filter;
            bool forward;
            std::optional<std::uint64_t> new_group_request;
        };

        explicit Subscribe(Parsed p)
          : request_id(p.request_id)
          , track_namespace(std::move(p.track_namespace))
          , track_name(std::move(p.track_name))
          , auth_tokens(std::move(p.auth_tokens))
          , object_delivery_timeout(p.object_delivery_timeout)
          , subgroup_delivery_timeout(p.subgroup_delivery_timeout)
          , rendezvous_timeout(p.rendezvous_timeout)
          , subscriber_priority(p.subscriber_priority)
          , group_order(p.group_order)
          , subscription_filter(std::move(p.subscription_filter))
          , forward(p.forward)
          , new_group_request(p.new_group_request)
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            p.track_namespace = reader.Read<TrackNamespace>();
            p.track_name = reader.Read<TrackName>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params,
                               { ParameterType::kAuthorizationToken,
                                 ParameterType::kDeliveryTimeout,
                                 ParameterType::kSubgroupDeliveryTimeout,
                                 ParameterType::kRendezvousTimeout,
                                 ParameterType::kSubscriberPriority,
                                 ParameterType::kGroupOrder,
                                 ParameterType::kLocationFilter,
                                 ParameterType::kSubgroupFilter,
                                 ParameterType::kObjectFilter,
                                 ParameterType::kPriorityFilter,
                                 ParameterType::kPropertyFilter,
                                 ParameterType::kTrackFilter,
                                 ParameterType::kForward,
                                 ParameterType::kNewGroupRequest });

            p.auth_tokens = CollectAuthTokens(params);
            p.object_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kDeliveryTimeout);
            p.subgroup_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kSubgroupDeliveryTimeout);
            p.rendezvous_timeout = params.GetOptional<std::uint64_t>(ParameterType::kRendezvousTimeout).value_or(0);
            p.subscriber_priority = params.GetOptional<std::uint8_t>(ParameterType::kSubscriberPriority).value_or(128);
            p.group_order = ResolveGroupOrder(params);
            p.subscription_filter = ResolveFilter(params);
            p.forward = ResolveForward(params, true);
            p.new_group_request = params.GetOptional<std::uint64_t>(ParameterType::kNewGroupRequest);
            return p;
        }
    };

} // namespace quicr::messages::control
