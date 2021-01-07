using System;
using MultiPlug.Base.Security;

namespace MultiPlug.Auth.Local.Models
{
    class AuthResult : IAuthResult
    {
        public string Message { get; set; }

        public bool Result { get; set; }
    }
}
