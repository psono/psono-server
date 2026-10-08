def _scrypt_factors(parameters):
    try:
        values = [parameters[name] for name in ("u", "r", "p")]
    except (KeyError, TypeError):
        return None
    if not all(
        (type(value) is int or (type(value) is float and value.is_integer()))
        and value > 0
        for value in values
    ):
        return None
    return tuple(int(value) for value in values)


def _compare_scaled(first, first_exponent, second, second_exponent):
    """Compare integer * 2**exponent without allocating an unbounded power."""
    first_bits = first.bit_length() + first_exponent
    second_bits = second.bit_length() + second_exponent
    if first_bits != second_bits:
        return (first_bits > second_bits) - (first_bits < second_bits)
    difference = first_exponent - second_exponent
    if difference >= 0:
        first <<= difference
    else:
        second <<= -difference
    return (first > second) - (first < second)


def is_weaker_hashing_profile(
    algorithm, parameters, target_algorithm, target_parameters
):
    """Compare scrypt's dominant memory (N*r) and CPU (N*r*p) work costs.

    Equal costs, memory/CPU trade-offs, and unknown algorithms are not weaker.
    Output length is a credential format parameter, not a scrypt work factor.
    """
    if algorithm != "scrypt" or target_algorithm != algorithm:
        return False
    old = _scrypt_factors(parameters)
    target = _scrypt_factors(target_parameters)
    if old is None or target is None:
        return False
    old_u, old_r, old_p = old
    new_u, new_r, new_p = target
    memory = _compare_scaled(old_r, old_u, new_r, new_u)
    cpu = _compare_scaled(old_r * old_p, old_u, new_r * new_p, new_u)
    return memory <= 0 and cpu <= 0 and (memory < 0 or cpu < 0)
