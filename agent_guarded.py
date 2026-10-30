"""The guarded agent: the same agent, with the security guard checking tools, calls and results."""
import sys

from langchain.agents import create_agent

from agent import SYSTEM_PROMPT, ask
from guard import Guard
from guard.toolscan import (PinStore, blocked_tool_for_prompt, friendly_block_message, reply_for_fake_tool_call,
                            vet_tool_defs)
from guard.wrap import check_user_input, guard_tool
from llm import get_llm
from mcp_client import get_bridge, load_mcp_tools


def build_guarded_agent(guard: Guard | None = None, servers=None, pins: "PinStore | None" = "default",
                        extra_prompt: str = ""):
    """Agent whose MCP tools are vetted (definitions) and wrapped (calls + results) by the guard.

    Servers listed earlier are trusted more (a later server cannot shadow an earlier server's tool).
    Findings from vetting are kept on `guard.tool_findings`.
    """
    guard = guard or Guard()
    pins = PinStore() if pins == "default" else pins  # "default" means: use the saved pin file

    # Vetting step: scan every tool definition and drop the ones the guard blocks.
    def vet(defs):
        allowed, findings = vet_tool_defs(defs, guard, pins)
        guard.tool_findings = findings  # kept so the UI can show what was removed and why
        guard.allowed_names = {d.name for d in allowed}  # every tool the model really has
        return allowed

    # Every surviving tool is wrapped so its calls and results are checked too. The guard sits on the
    # client side, so it does not depend on trusting any MCP server.
    tools = [guard_tool(t, guard) for t in load_mcp_tools(servers, vet=vet)]
    # Deliberately NOT told which tools were removed: naming them in the prompt makes small models try to call them.
    return create_agent(get_llm(), tools, system_prompt=SYSTEM_PROMPT + extra_prompt), guard


def tool_notice(guard: Guard, question: str) -> str | None:
    """Friendly reply if the user names a tool the guard removed (the LLM is not needed for that)."""
    hit = blocked_tool_for_prompt(question, getattr(guard, "tool_findings", []))
    return friendly_block_message(hit) if hit else None


def clean_answer(guard: Guard, answer: str) -> str:
    """Turn a written-out call to an unavailable tool into a plain explanation."""
    available = {t.name for t in get_bridge().tools} | getattr(guard, "allowed_names", set())  # tools the model really has
    return reply_for_fake_tool_call(answer, getattr(guard, "tool_findings", []), available) or answer


def ask_guarded(agent, guard: Guard, question: str) -> str:
    """Ask a question with all checks: refuse bad input first, then explain removed tools, then answer."""
    guard.current_question = question  # a write tool may only touch a file this message names
    refusal = check_user_input(question, guard)
    if refusal:
        return refusal  # the LLM is never called
    return tool_notice(guard, question) or clean_answer(guard, ask(agent, question))


# Command-line use: one question as arguments, or an interactive chat when run without arguments.
if __name__ == "__main__":
    agent, guard = build_guarded_agent()
    if len(sys.argv) > 1:
        print(ask_guarded(agent, guard, " ".join(sys.argv[1:])))
    else:
        print("Guarded agent ready. Ctrl+C to quit.")
        while True:
            q = input("\nyou> ").strip()
            if q:
                print("agent>", ask_guarded(agent, guard, q))
