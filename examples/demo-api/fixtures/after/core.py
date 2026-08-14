"""Pure query boundary used by the fixed demo and its unit tests."""

MAX_PAGE_SIZE = 100


def build_user_search(term: str, page_size: int) -> tuple[str, tuple[str, int]]:
    if not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")
    query = "SELECT id, email FROM users WHERE email LIKE ? LIMIT ?"
    return query, (f"%{term}%", page_size)
