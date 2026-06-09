# src/orin/analysis/sigma.py
"""
orin.analysis.sigma – Sigma Rule Parser & Evaluator
==================================================
Provides offline, zero-dependency parsing of Sigma rules (in YAML format)
and evaluates them against captured authentication log lines.
"""
import ast
from pathlib import Path

# Set default rule level classifications
VALID_LEVELS = {"low", "medium", "high", "critical"}


def parse_yaml_rule(content: str) -> dict:
    """A zero-dependency YAML-to-dict parser tailored for Sigma rules."""
    lines = content.splitlines()
    data = {}
    stack = [(-1, data)]  # stack of (indentation, current_dict_or_list)

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Pop from stack if indent is less than or equal to current top
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        current_parent = stack[-1][1]

        # Check if line is a list item
        if stripped.startswith("-"):
            val = stripped[1:].strip().strip("'\"")
            if isinstance(current_parent, list):
                current_parent.append(val)
            continue

        if ":" not in stripped:
            continue

        key, val = stripped.split(":", 1)
        key = key.strip()
        val = val.strip().strip("'\"")

        if val == "":
            # Lookahead to determine nested type (list vs dict)
            is_list = False
            for next_line in lines[i + 1:]:
                next_stripped = next_line.strip()
                if not next_stripped or next_stripped.startswith("#"):
                    continue
                if next_stripped.startswith("-"):
                    is_list = True
                break

            new_obj = [] if is_list else {}
            if isinstance(current_parent, dict):
                current_parent[key] = new_obj
            elif isinstance(current_parent, list):
                current_parent.append({key: new_obj})

            stack.append((indent, new_obj))
        else:
            if isinstance(current_parent, dict):
                current_parent[key] = val
            elif isinstance(current_parent, list):
                current_parent.append({key: val})

    return data


def _safe_eval_ast(node: ast.AST) -> bool:
    """Recursively and safely evaluate a boolean AST expression.

    Parameters
    ----------
    node : ast.AST
        The AST node to evaluate.

    Returns
    -------
    bool
        The evaluated boolean result.

    Raises
    ------
    ValueError
        If an unsupported AST node type is encountered.
    """
    if isinstance(node, ast.Expression):
        return _safe_eval_ast(node.body)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
    elif isinstance(node, ast.Name):
        if node.id == "True":
            return True
        elif node.id == "False":
            return False
    elif isinstance(node, ast.BoolOp):
        values = [_safe_eval_ast(val) for val in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        elif isinstance(node.op, ast.Or):
            return any(values)
    elif isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _safe_eval_ast(node.operand)
    raise ValueError(f"Unsupported AST node type: {type(node)}")


def evaluate_condition(condition_str: str, selector_values: dict[str, bool]) -> bool:
    """Evaluate the condition string expression using mapped selector values."""
    tokens = condition_str.lower().split()
    if not tokens:
        return False

    evaluated_tokens = []
    i = 0
    while i < len(tokens):
        token = tokens[i]

        # Handle '1 of prefix*' or 'all of prefix*'
        if token in ("1", "all") and i + 2 < len(tokens) and tokens[i + 1] == "of":
            target = tokens[i + 2]
            # Strip trailing wildcard or parenthesis
            clean_target = target.rstrip(")").rstrip("*")

            matches = [val for name, val in selector_values.items() if name.startswith(clean_target)]

            if token == "1":
                result = any(matches) if matches else False
            else:
                result = all(matches) if matches else False

            evaluated_tokens.append(str(result))

            # If target had closing parenthesis, preserve it
            if target.endswith(")"):
                evaluated_tokens.append(")")

            i += 3
            continue

        if token in ("and", "or", "not", "(", ")"):
            evaluated_tokens.append(token)
        elif token in selector_values:
            evaluated_tokens.append(str(selector_values[token]))
        else:
            evaluated_tokens.append("False")
        i += 1

    eval_str = " ".join(evaluated_tokens)

    # Restrict allowed keywords for safe evaluation
    allowed_words = {"true", "false", "and", "or", "not", "(", ")"}
    if all(w in allowed_words for w in eval_str.lower().split()):
        try:
            tree = ast.parse(eval_str, mode="eval")
            return _safe_eval_ast(tree)
        except Exception:
            return False
    return False


def evaluate_rule_against_log(log_line: str, rule: dict) -> bool:
    """Check if a log line matches the Sigma rule detection logic."""
    detection = rule.get("detection")
    if not detection or "condition" not in detection:
        return False

    selector_values = {}

    # Evaluate each selector list in detection
    for selector_name, criteria in detection.items():
        if selector_name == "condition":
            continue

        # Criteria can be a single string or list of strings
        if isinstance(criteria, str):
            criteria = [criteria]

        matched = False
        if isinstance(criteria, list):
            for pattern in criteria:
                if str(pattern).lower() in log_line.lower():
                    matched = True
                    break
        elif isinstance(criteria, dict):
            # E.g. field matching, check if any criteria matches as substring
            for k, val in criteria.items():
                if isinstance(val, list):
                    for v in val:
                        if str(v).lower() in log_line.lower():
                            matched = True
                            break
                else:
                    if str(val).lower() in log_line.lower():
                        matched = True
                        break

        selector_values[selector_name] = matched

    condition = detection["condition"]
    return evaluate_condition(condition, selector_values)


def load_rules(rules_dir: Path) -> list[dict]:
    """Scan directory and load all valid Sigma rules."""
    rules = []
    if not rules_dir.exists() or not rules_dir.is_dir():
        return rules

    for rule_file in rules_dir.glob("*.yml"):
        try:
            content = rule_file.read_text(encoding="utf-8")
            rule = parse_yaml_rule(content)
            if "title" in rule and "detection" in rule:
                rule["file_path"] = str(rule_file)
                rules.append(rule)
        except Exception:
            continue
    return rules