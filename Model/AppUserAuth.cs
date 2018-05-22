using System.Collections.Generic;

namespace PtcApi.Model
{
    public class AppUserAuth
    {
        public string UserName { get; set; }
        public string BearerToken { get; set; }
        public bool IsAuthenticated { get; set; }

        public List<AppUserClaim> Claims { get; set; }
        
        public AppUserAuth() : base()
        {
            UserName = "Not authorized";
            BearerToken = string.Empty;
        }
    }
}