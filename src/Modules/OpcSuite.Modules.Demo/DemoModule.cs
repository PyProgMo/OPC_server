using Microsoft.Extensions.Logging;
using OpcSuite.Core.AddressSpace;
using OpcSuite.Core.Modules;

namespace OpcSuite.Modules.Demo;

/// <summary>
/// Example module and template for new ones: a counter, a clock, two writable values and a simulated
/// temperature that follows the writable setpoint.
/// </summary>
public sealed class DemoModule : IServerModule
{
    private ILogger? _logger;
    private IVariableNode<int>? _counter;
    private IVariableNode<DateTime>? _clock;
    private IVariableNode<double>? _setpoint;
    private IVariableNode<double>? _temperature;
    private CancellationTokenSource? _stop;
    private Task? _loop;

    public string Name => "Demo";

    public void CreateNodes(IModuleContext context)
    {
        _logger = context.Logger;

        _counter = context.Root.AddVariable("Counter", 0, description: "Increments once per second");
        _clock = context.Root.AddVariable("Clock", DateTime.UtcNow, description: "Server time (UTC)");
        _setpoint = context.Root.AddVariable("Setpoint", 20.0, NodeAccess.ReadWrite, "Target temperature, writable");
        var message = context.Root.AddVariable("Message", "Hello from OpcSuite", NodeAccess.ReadWrite, "Free text, writable");
        _temperature = context.Root.AddFolder("Sensors").AddVariable("Temperature", 20.0, description: "Follows the setpoint");

        _setpoint.WrittenByClient += value => _logger.LogInformation("Setpoint changed to {Value}", value);
        message.WrittenByClient += value => _logger.LogInformation("Message changed to '{Value}'", value);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _stop = new CancellationTokenSource();
        _loop = RunAsync(_stop.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_stop is null || _loop is null)
        {
            return;
        }
        await _stop.CancelAsync().ConfigureAwait(false);
        await _loop.ConfigureAwait(false);
        _stop.Dispose();
    }

    private async Task RunAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            {
                _counter!.Value++;
                _clock!.Value = DateTime.UtcNow;
                _temperature!.Value += (_setpoint!.Value - _temperature.Value) * 0.2;
            }
        }
        catch (OperationCanceledException)
        {
            // module is stopping
        }
    }
}
