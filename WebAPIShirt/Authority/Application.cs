using System.Security;

namespace WebAPIShirt.Authority
{
    public class Application
    {
        public int ApplicationId { get; set; }
        public string? ApplicationName { get; set; }
        public string? ClientId { get; set; } //Username
        public string? Secret { get; set; } //Password
        public string? Scopes { get; set; }
    }
}
