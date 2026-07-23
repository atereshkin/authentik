"""Stage marker tests"""

from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.test import TestCase

from authentik.core.tests.utils import RequestFactory, create_test_flow, create_test_user
from authentik.flows.markers import ReevaluateMarker
from authentik.flows.models import FlowStageBinding
from authentik.flows.planner import (
    PLAN_CONTEXT_PENDING_USER,
    PLAN_CONTEXT_POLICY_EXCLUSIONS,
    FlowPlan,
)
from authentik.lib.generators import generate_id
from authentik.policies.types import PolicyResult
from authentik.stages.dummy.models import DummyStage


class TestReevaluateMarkerExclusions(TestCase):
    """A binding dropped by a failed policy re-evaluation is recorded in the plan
    context so the executor can interpret the flow's outcome; passing re-evaluations
    record nothing."""

    def setUp(self):
        self.request_factory = RequestFactory()
        self.flow = create_test_flow()
        self.user = create_test_user()

    def _request(self, user=None):
        request = self.request_factory.get("/")
        request.user = user or AnonymousUser()
        return request

    def _binding(self, stage):
        return FlowStageBinding.objects.create(
            target=self.flow, stage=stage, order=0, re_evaluate_policies=True
        )

    def _plan(self, **context):
        plan = FlowPlan(flow_pk=self.flow.pk.hex)
        plan.context.update(context)
        return plan

    def _process(self, binding, result, plan, request):
        marker = ReevaluateMarker(binding=binding)
        with patch("authentik.flows.markers.PolicyEngine") as engine:
            engine.return_value.result = result
            return marker.process(plan, binding, request)

    def test_exclusion_recorded(self):
        """A failed re-evaluation removes the binding and records the stage name,
        the denial messages and the reasons in the plan context."""
        stage = DummyStage.objects.create(name=generate_id())
        binding = self._binding(stage)
        result = PolicyResult(False, "too far", reasons={"impossible_travel"})
        plan = self._plan(**{PLAN_CONTEXT_PENDING_USER: self.user})

        returned = self._process(binding, result, plan, self._request(self.user))

        self.assertIsNone(returned)
        self.assertEqual(
            plan.context[PLAN_CONTEXT_POLICY_EXCLUSIONS],
            [
                {
                    "stage": stage.name,
                    "messages": ["too far"],
                    "reasons": ["impossible_travel"],
                }
            ],
        )

    def test_exclusions_append(self):
        """Multiple failed re-evaluations in one plan append, keeping earlier records."""
        first = self._binding(DummyStage.objects.create(name=generate_id()))
        second = self._binding(DummyStage.objects.create(name=generate_id()))
        plan = self._plan(**{PLAN_CONTEXT_PENDING_USER: self.user})

        self._process(first, PolicyResult(False, "one"), plan, self._request(self.user))
        self._process(second, PolicyResult(False, "two"), plan, self._request(self.user))

        exclusions = plan.context[PLAN_CONTEXT_POLICY_EXCLUSIONS]
        self.assertEqual(
            [exclusion["stage"] for exclusion in exclusions], [first.stage.name, second.stage.name]
        )
        self.assertEqual([exclusion["messages"] for exclusion in exclusions], [["one"], ["two"]])

    def test_nothing_recorded_when_passing(self):
        """A passing re-evaluation keeps the binding and records nothing."""
        binding = self._binding(DummyStage.objects.create(name=generate_id()))
        plan = self._plan(**{PLAN_CONTEXT_PENDING_USER: self.user})

        returned = self._process(binding, PolicyResult(True), plan, self._request(self.user))

        self.assertEqual(returned, binding)
        self.assertNotIn(PLAN_CONTEXT_POLICY_EXCLUSIONS, plan.context)
