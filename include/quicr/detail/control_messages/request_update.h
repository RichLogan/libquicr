// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    struct RequestUpdate
    {
        static constexpr std::uint64_t kType = 0x2;

        const RequestID request_id;
        const std::vector<Token> auth_tokens;
        const std::optional<std::uint64_t> object_delivery_timeout;
        const std::optional<std::uint64_t> subgroup_delivery_timeout;
        const std::optional<std::uint8_t> subscriber_priority;
        const std::optional<Filter> subscription_filter;
        const std::optional<bool> forward;
        const std::optional<std::uint64_t> new_group_request;
        const std::optional<TrackNamespace> track_namespace_prefix;

        explicit RequestUpdate(BytesSpan payload)
          : RequestUpdate(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            RequestID request_id;
            std::vector<Token> auth_tokens;
            std::optional<std::uint64_t> object_delivery_timeout;
            std::optional<std::uint64_t> subgroup_delivery_timeout;
            std::optional<std::uint8_t> subscriber_priority;
            std::optional<Filter> subscription_filter;
            std::optional<bool> forward;
            std::optional<std::uint64_t> new_group_request;
            std::optional<TrackNamespace> track_namespace_prefix;
        };

        explicit RequestUpdate(Parsed p)
          : request_id(p.request_id)
          , auth_tokens(std::move(p.auth_tokens))
          , object_delivery_timeout(p.object_delivery_timeout)
          , subgroup_delivery_timeout(p.subgroup_delivery_timeout)
          , subscriber_priority(p.subscriber_priority)
          , subscription_filter(std::move(p.subscription_filter))
          , forward(p.forward)
          , new_group_request(p.new_group_request)
          , track_namespace_prefix(std::move(p.track_namespace_prefix))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            Parsed p;
            p.request_id = reader.Read<RequestID>();
            const auto params = reader.Read<Parameters>();
            reader.ExpectDone();

            ValidateParameters(params,
                               { ParameterType::kAuthorizationToken,
                                 ParameterType::kDeliveryTimeout,
                                 ParameterType::kSubgroupDeliveryTimeout,
                                 ParameterType::kSubscriberPriority,
                                 ParameterType::kLocationFilter,
                                 ParameterType::kSubgroupFilter,
                                 ParameterType::kObjectFilter,
                                 ParameterType::kPriorityFilter,
                                 ParameterType::kPropertyFilter,
                                 ParameterType::kTrackFilter,
                                 ParameterType::kForward,
                                 ParameterType::kNewGroupRequest,
                                 ParameterType::kTrackNamespacePrefix });

            p.auth_tokens = CollectAuthTokens(params);
            p.object_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kDeliveryTimeout);
            p.subgroup_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kSubgroupDeliveryTimeout);
            p.subscriber_priority = params.GetOptional<std::uint8_t>(ParameterType::kSubscriberPriority);

            if (params.Contains(ParameterType::kLocationFilter) || params.Contains(ParameterType::kSubgroupFilter) ||
                params.Contains(ParameterType::kObjectFilter) || params.Contains(ParameterType::kPriorityFilter) ||
                params.Contains(ParameterType::kPropertyFilter) || params.Contains(ParameterType::kTrackFilter)) {
                p.subscription_filter = ResolveFilter(params);
            }

            if (params.Contains(ParameterType::kForward)) {
                p.forward = ResolveForward(params, true);
            }

            p.new_group_request = params.GetOptional<std::uint64_t>(ParameterType::kNewGroupRequest);
            p.track_namespace_prefix = params.GetOptional<TrackNamespace>(ParameterType::kTrackNamespacePrefix);
            return p;
        }
    };

} // namespace quicr::messages::control
