namespace WebAPIShirt.Authority
{
    public static class AppRepository
    {
        private static List<Application> _applications = new List<Application>()
        {
            new Application
            {
                ApplicationId = 1,
                ApplicationName = "MVCWebApp",
                ClientId = "E0790E15-01D3-42C9-B4CD-9AA65B12FFE1", //secret e clientId generati da SQl server:
                Secret = "45C01F42-09C2-49DD-9436-5E50646155B6", //SELECT NEWID() AS ClientId, NEWID() AS Secret
                Scopes = "read,write"
            }
        };

        

        public static Application? GetApplicationByClientId(string clientId)
        {
            return _applications.FirstOrDefault(a => a.ClientId == clientId);
        }


    }
}
