namespace OpenIddictAuthorizationServer.Models;

public class PaginationResponse<T>
{
    public int TotalRecords { get; set; }
    public int PageSize { get; set; }
    public int PageNumber { get; set; }
    public int TotalPages { get; set; }

    public List<T> Items { get; set; } = new List<T>();
}
