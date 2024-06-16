namespace WebApplication2.Middlewares;
using System.Net;
public class ErrorHandling
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandling> _logger;

    public ErrorHandling(RequestDelegate next, ILogger<ErrorHandling> loger)
    {
        _next = next;
        _logger = loger; //opcjonalny zeby zapisac błedy
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred");
            await HandleExceptionAsync(context, ex);
        }
    }

    private Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        context.Response.ContentType = "application/json";

        var response = new
        {
            error = new
            {
                message = "An error occurred while processing your request.",
                detail = exception.Message
            }
        };

        return context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response));
    }
}