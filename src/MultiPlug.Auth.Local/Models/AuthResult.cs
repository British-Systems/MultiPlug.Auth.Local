using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Local.Models
{
    internal class AuthResult : IAuthResult
    {
        internal AuthResult()
        {
        }

        internal AuthResult(bool theResult, IUser theUser, string theMessage)
        {
            Result = theResult;
            Message = theMessage;
            User = theUser;
        }

        public IUser User { get; set; } = null;
        public string Message { get; set; } = string.Empty;
        public bool Result { get; set; }
    }
}
