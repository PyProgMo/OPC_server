namespace OpcSuite.Server.Security;

/// <summary>
/// Slows down password guessing. After <c>maxFailures</c> failed logins in a row a user name is locked for
/// <c>lockout</c>. Until its failures are forgotten, every further failure locks it again at once, which holds
/// guessing to one attempt per lockout period. Failures are forgotten after a successful login or after a quiet
/// period of at least 15 minutes. Names are tracked whether or not such a user exists, so a lockout tells an
/// attacker nothing about which users exist.
/// </summary>
public sealed class LoginThrottle
{
    private const int MaxTrackedNames = 10_000;
    private static readonly TimeSpan MinimumMemory = TimeSpan.FromMinutes(15);

    private readonly int _maxFailures;
    private readonly TimeSpan _lockout;
    private readonly TimeSpan _memory;
    private readonly TimeProvider _time;
    private readonly Dictionary<string, (int Failures, DateTimeOffset Last)> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    /// <param name="maxFailures">Failed logins in a row before the lockout starts; 0 switches the throttle off.</param>
    public LoginThrottle(int maxFailures, TimeSpan lockout, TimeProvider? time = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxFailures);
        ArgumentOutOfRangeException.ThrowIfLessThan(lockout, TimeSpan.Zero);
        _maxFailures = maxFailures;
        _lockout = lockout;
        _memory = lockout * 2 > MinimumMemory ? lockout * 2 : MinimumMemory;
        _time = time ?? TimeProvider.System;
    }

    public bool IsLockedOut(string name, out TimeSpan remaining)
    {
        remaining = TimeSpan.Zero;
        if (_maxFailures == 0)
        {
            return false;
        }
        lock (_lock)
        {
            if (!_failures.TryGetValue(name, out var state) || state.Failures < _maxFailures)
            {
                return false;
            }
            remaining = state.Last + _lockout - _time.GetUtcNow();
            return remaining > TimeSpan.Zero;
        }
    }

    public void RecordFailure(string name)
    {
        if (_maxFailures == 0)
        {
            return;
        }
        lock (_lock)
        {
            var now = _time.GetUtcNow();
            if (_failures.Count >= MaxTrackedNames)
            {
                Forget(now);
            }
            var failures = _failures.TryGetValue(name, out var state) && now - state.Last <= _memory ? state.Failures + 1 : 1;
            _failures[name] = (failures, now);
        }
    }

    public void RecordSuccess(string name)
    {
        lock (_lock)
        {
            _failures.Remove(name);
        }
    }

    private void Forget(DateTimeOffset now)
    {
        foreach (var stale in _failures.Where(f => now - f.Value.Last > _memory).Select(f => f.Key).ToList())
        {
            _failures.Remove(stale);
        }
        if (_failures.Count >= MaxTrackedNames)
        {
            // only reachable when someone tries thousands of names; keep memory bounded rather than history
            _failures.Clear();
        }
    }
}
