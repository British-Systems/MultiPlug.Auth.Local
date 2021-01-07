using System;
using System.IO;
using System.Linq;
using System.Xml.Serialization;
using System.Collections.Generic;

using MultiPlug.Base.Security;
using MultiPlug.Auth.Local.Models;

namespace MultiPlug.Auth.Local
{
    public class LocalAuthentication : IAuthentication
    {
        private string[] m_Domains;

        private const string m_AuthFile = "MultiPlug.Auth.Local.config";

        public LocalAuthentication()
        {
            m_Domains = new string[] { "Local" };

            if ( ! File.Exists( m_AuthFile ) )
            {
                AuthLocalFile NewFile = new AuthLocalFile
                {
                    Users = new User[]
                    {
                        new User { Enabled = false, Username = "admin", Password = "password" }
                    }
                };

                try
                {
                    XmlSerializer Serializer = new XmlSerializer( typeof( AuthLocalFile ) );
                    using ( Stream stream = new FileStream( m_AuthFile, FileMode.Create, FileAccess.Write, FileShare.None ) )
                    {
                        Serializer.Serialize(stream, NewFile);
                    }
                }
                catch { }
            }
        }
        public IReadOnlyCollection<string> Domains
        {
            get
            {
                return Array.AsReadOnly( m_Domains);
            }
        }

        public IAuthResult Authenticate( IAuthCredentials theCredentials)
        {
            AuthLocalFile AuthFileRoot = null;

            if ( ! File.Exists( m_AuthFile ) )
            {
                return new AuthResult { Result = false, Message = "System Error: Lookup file does not exist" };
            }

            try
            {
                XmlSerializer Serializer = new XmlSerializer( typeof( AuthLocalFile ) );
                using (Stream stream = new FileStream( m_AuthFile, FileMode.Open, FileAccess.Read, FileShare.Read ) )
                {
                    AuthFileRoot = (AuthLocalFile)Serializer.Deserialize( stream );
                }
            }
            catch ( InvalidOperationException ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message };
            }
            catch ( FileNotFoundException ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message };
            }
            catch ( Exception ex )
            {
                return new AuthResult { Result = false, Message = "System Error: " + ex.Message };
            }

            var UserSearch = AuthFileRoot.Users.FirstOrDefault( u => u.Username.Equals( theCredentials.Username, StringComparison.OrdinalIgnoreCase ) );

            if( UserSearch == null )
            {
                return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
            }
            else
            {
                if( ! UserSearch.Enabled )
                {
                    return new AuthResult { Result = false, Message = "User is disabled" };
                }
                else
                {
                    if ( UserSearch.Password != theCredentials.Password )
                    {
                        return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                    }
                    else
                    {
                        return new AuthResult { Result = true, Message = "OK" };
                    }
                }
            }
        }
    }
}
