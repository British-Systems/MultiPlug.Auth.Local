using System;
using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Local.Models
{
    class AuthResult : IAuthResult
    {
        public string Identity { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool Result { get; set; }
    }
}
