"""Safety helpers applied at export rendering boundaries."""


_CSV_LEADING_IGNORABLE = " \t\r\n"
_CSV_FORMULA_PREFIXES = "=+-@"


def neutralize_csv_cell(value):
    """Prefix spreadsheet-formula-like strings without altering their content."""
    if not isinstance(value, str):
        return value

    significant = value.lstrip(_CSV_LEADING_IGNORABLE)
    if significant and significant[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value
