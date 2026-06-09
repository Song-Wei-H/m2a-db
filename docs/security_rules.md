\# Non-Negotiable Security Rules



\- LLM must never execute raw shell

\- subprocess must always use shell=False

\- Only allowlisted tools are executable

\- Human approval required for exploit tools

\- Dispatcher validates all tasks

\- Worker cannot receive arbitrary command

\- No command/shell/args from LLM

\- ALLOWED\_SCOPES enforced

\- No hydra

