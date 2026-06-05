// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "quicr/detail/control_messages/message_reader.h"
#include "quicr/detail/control_messages/parameters.h"

namespace quicr::messages::control {

    // Shared envelope for every *_OK message: a parameter block followed by track properties.
    struct OkEnvelope
    {
        Parameters parameters;
        TrackExtensions track_properties;
    };

    inline OkEnvelope ReadOkEnvelope(MessageReader& reader)
    {
        OkEnvelope envelope;
        envelope.parameters = reader.Read<Parameters>();
        envelope.track_properties = reader.Read<TrackExtensions>();
        reader.ExpectDone();
        return envelope;
    }

    struct PublishOk
    {
        static constexpr std::uint64_t kType = 0x7;

        const std::optional<std::uint64_t> object_delivery_timeout;
        const std::optional<std::uint64_t> subgroup_delivery_timeout;
        const std::uint8_t subscriber_priority;
        const std::optional<GroupOrder> group_order;
        const Filter subscription_filter;
        const std::optional<std::uint64_t> expires;
        const bool forward;
        const std::optional<std::uint64_t> new_group_request;
        const TrackExtensions track_properties;

        explicit PublishOk(BytesSpan payload)
          : PublishOk(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            std::optional<std::uint64_t> object_delivery_timeout;
            std::optional<std::uint64_t> subgroup_delivery_timeout;
            std::uint8_t subscriber_priority;
            std::optional<GroupOrder> group_order;
            Filter subscription_filter;
            std::optional<std::uint64_t> expires;
            bool forward;
            std::optional<std::uint64_t> new_group_request;
            TrackExtensions track_properties;
        };

        explicit PublishOk(Parsed p)
          : object_delivery_timeout(p.object_delivery_timeout)
          , subgroup_delivery_timeout(p.subgroup_delivery_timeout)
          , subscriber_priority(p.subscriber_priority)
          , group_order(p.group_order)
          , subscription_filter(std::move(p.subscription_filter))
          , expires(p.expires)
          , forward(p.forward)
          , new_group_request(p.new_group_request)
          , track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            auto envelope = ReadOkEnvelope(reader);
            const auto& params = envelope.parameters;

            ValidateParameters(params,
                               { ParameterType::kDeliveryTimeout,
                                 ParameterType::kSubgroupDeliveryTimeout,
                                 ParameterType::kSubscriberPriority,
                                 ParameterType::kGroupOrder,
                                 ParameterType::kLocationFilter,
                                 ParameterType::kSubgroupFilter,
                                 ParameterType::kObjectFilter,
                                 ParameterType::kPriorityFilter,
                                 ParameterType::kPropertyFilter,
                                 ParameterType::kTrackFilter,
                                 ParameterType::kExpires,
                                 ParameterType::kForward,
                                 ParameterType::kNewGroupRequest });

            Parsed p;
            p.object_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kDeliveryTimeout);
            p.subgroup_delivery_timeout = params.GetOptional<std::uint64_t>(ParameterType::kSubgroupDeliveryTimeout);
            p.subscriber_priority = params.GetOptional<std::uint8_t>(ParameterType::kSubscriberPriority).value_or(128);
            p.group_order = ResolveGroupOrder(params);
            p.subscription_filter = ResolveFilter(params);
            p.expires = ResolveExpires(params);
            p.forward = ResolveForward(params, true);
            p.new_group_request = params.GetOptional<std::uint64_t>(ParameterType::kNewGroupRequest);
            p.track_properties = std::move(envelope.track_properties);
            return p;
        }
    };

    struct RequestUpdateOk
    {
        static constexpr std::uint64_t kType = 0x7;

        const std::optional<std::uint64_t> expires;
        const std::optional<Location> largest_object;
        const TrackExtensions track_properties;

        explicit RequestUpdateOk(BytesSpan payload)
          : RequestUpdateOk(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            std::optional<std::uint64_t> expires;
            std::optional<Location> largest_object;
            TrackExtensions track_properties;
        };

        explicit RequestUpdateOk(Parsed p)
          : expires(p.expires)
          , largest_object(p.largest_object)
          , track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            auto envelope = ReadOkEnvelope(reader);
            const auto& params = envelope.parameters;

            ValidateParameters(params, { ParameterType::kExpires, ParameterType::kLargestObject });

            Parsed p;
            p.expires = ResolveExpires(params);
            p.largest_object = params.GetOptional<Location>(ParameterType::kLargestObject);
            p.track_properties = std::move(envelope.track_properties);
            return p;
        }
    };

    struct TrackStatusOk
    {
        static constexpr std::uint64_t kType = 0x7;

        const std::optional<Location> largest_object;
        const TrackExtensions track_properties;

        explicit TrackStatusOk(BytesSpan payload)
          : TrackStatusOk(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            std::optional<Location> largest_object;
            TrackExtensions track_properties;
        };

        explicit TrackStatusOk(Parsed p)
          : largest_object(p.largest_object)
          , track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            auto envelope = ReadOkEnvelope(reader);
            ValidateParameters(envelope.parameters, { ParameterType::kLargestObject });

            Parsed p;
            p.largest_object = envelope.parameters.GetOptional<Location>(ParameterType::kLargestObject);
            p.track_properties = std::move(envelope.track_properties);
            return p;
        }
    };

    // No-parameter OK messages: any parameter is a violation.
    struct EmptyOk
    {
        const TrackExtensions track_properties;

        explicit EmptyOk(BytesSpan payload)
          : EmptyOk(Parse(MessageReader{ payload }))
        {
        }

      private:
        struct Parsed
        {
            TrackExtensions track_properties;
        };

        explicit EmptyOk(Parsed p)
          : track_properties(std::move(p.track_properties))
        {
        }

        static Parsed Parse(MessageReader reader)
        {
            auto envelope = ReadOkEnvelope(reader);
            ValidateParameters(envelope.parameters, std::initializer_list<ParameterType>{});
            return Parsed{ std::move(envelope.track_properties) };
        }
    };

    struct PublishNamespaceOk : EmptyOk
    {
        static constexpr std::uint64_t kType = 0x7;
        using EmptyOk::EmptyOk;
    };

    struct SubscribeNamespaceOk : EmptyOk
    {
        static constexpr std::uint64_t kType = 0x7;
        using EmptyOk::EmptyOk;
    };

    struct SubscribeTracksOk : EmptyOk
    {
        static constexpr std::uint64_t kType = 0x7;
        using EmptyOk::EmptyOk;
    };

} // namespace quicr::messages::control
