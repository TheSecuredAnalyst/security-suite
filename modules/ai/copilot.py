"""AI Security Copilot - Natural language security analysis."""

import json
from collections.abc import AsyncIterator

from core.logger import get_logger
from core.models import ScanResult, Severity
from modules.ai.correlator import CorrelationReport, FindingCorrelator
from modules.ai.llm_client import BaseLLMClient, Message, get_llm_client

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and AI Security Copilot. Your role is to:

1. Analyze security scan results and identify critical issues
2. Correlate findings across different scans to identify attack patterns
3. Prioritize vulnerabilities based on real-world exploitability and business impact
4. Provide clear, actionable remediation guidance
5. Generate executive summaries suitable for non-technical stakeholders
6. Answer questions about the security posture in natural language

When analyzing findings:
- Focus on findings that could lead to actual compromise
- Consider attack chains and how vulnerabilities can be combined
- Prioritize based on: exploitability, impact, and exposure
- Provide specific remediation steps, not generic advice
- Reference industry standards (OWASP, CIS, NIST) where applicable

Always be direct and actionable. Security teams are busy - give them what they need to act.

Current scan data will be provided in JSON format. Analyze it thoroughly before responding."""


class SecurityCopilot:
    """AI-powered security analysis assistant."""

    def __init__(
        self,
        provider: str = "anthropic",
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        """Initialize Security Copilot.

        Args:
            provider: LLM provider - "anthropic", "openai", "ollama", "ollama/<model>",
                      or model shortcuts like "qwen", "llama3", "mistral"
            model: Model to use (defaults to provider's best)
            api_key: API key (or use environment variable)
            base_url: Base URL for API (for ollama or openai-compatible)

        Examples:
            SecurityCopilot("anthropic")
            SecurityCopilot("ollama", model="qwen2.5")
            SecurityCopilot("ollama/llama3.2")
            SecurityCopilot("qwen")  # shortcut for ollama/qwen2.5
            SecurityCopilot("openai-compatible", base_url="http://localhost:8000/v1", model="my-model")
        """
        self.logger = get_logger("ai.copilot")
        self.provider = provider
        self.correlator = FindingCorrelator()

        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if model:
            kwargs["model"] = model
        if base_url:
            kwargs["base_url"] = base_url

        self._client: BaseLLMClient | None = None
        self._client_kwargs = kwargs

        # Conversation history for context
        self.conversation: list[Message] = []
        self.scan_context: list[ScanResult] = []
        self.correlation_report: CorrelationReport | None = None

    def _get_client(self) -> BaseLLMClient:
        """Lazy load LLM client."""
        if self._client is None:
            self._client = get_llm_client(self.provider, **self._client_kwargs)
        return self._client

    def load_scan_results(self, results: list[ScanResult]) -> CorrelationReport:
        """Load scan results into copilot context.

        Args:
            results: List of scan results to analyze

        Returns:
            Correlation report from initial analysis
        """
        self.scan_context = results
        self.correlation_report = self.correlator.correlate(results)

        self.logger.info(
            f"Loaded {len(results)} scans with {self.correlation_report.total_findings} findings"
        )

        return self.correlation_report

    def _build_context(self) -> str:
        """Build context string from scan results."""
        if not self.scan_context:
            return "No scan data loaded."

        context = {
            "target": self.correlation_report.target if self.correlation_report else "Unknown",
            "scan_summary": {
                "total_scans": len(self.scan_context),
                "total_findings": self.correlation_report.total_findings if self.correlation_report else 0,
                "unique_findings": self.correlation_report.unique_findings if self.correlation_report else 0,
            },
            "risk_summary": self.correlation_report.risk_summary if self.correlation_report else {},
            "findings_by_severity": {},
            "findings": [],
            "attack_chains": [],
        }

        # Group findings by severity
        severity_groups = {s.value: [] for s in Severity}
        for result in self.scan_context:
            for finding in result.findings:
                severity_groups[finding.severity.value].append({
                    "title": finding.title,
                    "description": finding.description,
                    "source": finding.source,
                    "data": finding.data,
                })

        context["findings_by_severity"] = {
            k: v for k, v in severity_groups.items() if v
        }

        # Add attack chains
        if self.correlation_report:
            context["attack_chains"] = [
                {
                    "name": chain.name,
                    "description": chain.description,
                    "risk_score": chain.risk_score,
                    "finding_count": len(chain.findings),
                }
                for chain in self.correlation_report.attack_chains
            ]
            context["recommendations"] = self.correlation_report.recommendations

        return json.dumps(context, indent=2, default=str)

    async def ask(
        self,
        question: str,
        include_context: bool = True,
    ) -> str:
        """Ask the copilot a question about security findings.

        Args:
            question: Natural language question
            include_context: Whether to include scan context

        Returns:
            AI response
        """
        messages = [Message(role="system", content=SYSTEM_PROMPT)]

        # Add scan context if available and requested
        if include_context and self.scan_context:
            context = self._build_context()
            messages.append(Message(
                role="user",
                content=f"Here is the current scan data:\n\n```json\n{context}\n```\n\n"
                        "I'll now ask you questions about this data."
            ))
            messages.append(Message(
                role="assistant",
                content="I've analyzed the scan data. I can see the findings, risk levels, "
                        "and potential attack chains. What would you like to know?"
            ))

        # Add conversation history
        messages.extend(self.conversation)

        # Add current question
        messages.append(Message(role="user", content=question))

        # Get response
        client = self._get_client()
        response = await client.chat(messages, temperature=0.3)

        # Update conversation history
        self.conversation.append(Message(role="user", content=question))
        self.conversation.append(Message(role="assistant", content=response.content))

        # Trim conversation history if too long
        if len(self.conversation) > 20:
            self.conversation = self.conversation[-10:]

        return response.content

    async def stream_ask(
        self,
        question: str,
        include_context: bool = True,
    ) -> AsyncIterator[str]:
        """Stream response to a question.

        Args:
            question: Natural language question
            include_context: Whether to include scan context

        Yields:
            Response chunks
        """
        messages = [Message(role="system", content=SYSTEM_PROMPT)]

        if include_context and self.scan_context:
            context = self._build_context()
            messages.append(Message(
                role="user",
                content=f"Here is the current scan data:\n\n```json\n{context}\n```"
            ))
            messages.append(Message(
                role="assistant",
                content="I've analyzed the scan data. What would you like to know?"
            ))

        messages.extend(self.conversation)
        messages.append(Message(role="user", content=question))

        client = self._get_client()
        full_response = ""

        async for chunk in client.stream_chat(messages, temperature=0.3):
            full_response += chunk
            yield chunk

        # Update history
        self.conversation.append(Message(role="user", content=question))
        self.conversation.append(Message(role="assistant", content=full_response))

    async def analyze(self) -> str:
        """Get comprehensive analysis of loaded scan results.

        Returns:
            Detailed analysis report
        """
        if not self.scan_context:
            return "No scan data loaded. Use load_scan_results() first."

        prompt = """Provide a comprehensive security analysis including:

1. **Executive Summary** (2-3 sentences for leadership)
2. **Critical Findings** (top 5 issues that need immediate attention)
3. **Attack Surface Analysis** (how could an attacker exploit these findings?)
4. **Risk Assessment** (overall risk level with justification)
5. **Prioritized Remediation Plan** (ordered list of actions)
6. **Quick Wins** (easy fixes that significantly reduce risk)

Be specific and actionable. Reference actual findings from the data."""

        return await self.ask(prompt)

    async def get_executive_summary(self) -> str:
        """Generate executive summary for non-technical stakeholders.

        Returns:
            Executive-friendly summary
        """
        prompt = """Generate a brief executive summary (max 200 words) covering:

1. Overall security posture (Good/Fair/Poor/Critical)
2. Key risks in business terms (not technical jargon)
3. Recommended actions (high-level)
4. Comparison to industry standards if applicable

Write for a CEO or board member who needs to understand the risk without technical details."""

        return await self.ask(prompt)

    async def get_remediation_for(self, finding_title: str) -> str:
        """Get specific remediation guidance for a finding.

        Args:
            finding_title: Title of the finding to remediate

        Returns:
            Detailed remediation steps
        """
        prompt = f"""Provide detailed remediation guidance for: "{finding_title}"

Include:
1. Root cause explanation
2. Step-by-step fix instructions
3. Code examples if applicable
4. Verification steps to confirm the fix
5. Prevention measures for the future

Be specific and technical - this is for the engineering team."""

        return await self.ask(prompt)

    async def prioritize_findings(self) -> str:
        """Get prioritized list of findings with reasoning.

        Returns:
            Prioritized findings with justification
        """
        prompt = """Analyze all findings and provide a prioritized remediation order.

For each of the top 10 findings, explain:
1. Why it's prioritized at this level
2. Potential business impact if exploited
3. Estimated effort to fix (Low/Medium/High)
4. Dependencies on other fixes

Consider: exploitability, blast radius, ease of fix, and attack chain potential."""

        return await self.ask(prompt)

    def clear_conversation(self) -> None:
        """Clear conversation history."""
        self.conversation = []

    def clear_context(self) -> None:
        """Clear all context including scan results."""
        self.conversation = []
        self.scan_context = []
        self.correlation_report = None
