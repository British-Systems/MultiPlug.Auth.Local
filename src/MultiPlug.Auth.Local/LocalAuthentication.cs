using System;
using System.IO;
using System.Linq;
using System.Xml.Serialization;
using System.Collections.Generic;

using MultiPlug.Base.Security;
using MultiPlug.Auth.Local.Models;
using System.Text;

namespace MultiPlug.Auth.Local
{
    public class LocalAuthentication : IAuthentication
    {
        private const string m_AuthFile = "MultiPlug.Auth.Local.config";

        private static readonly string[] c_Domains = { "Local" };
        private static readonly Scheme[] c_Schemes = { Scheme.Form, Scheme.Basic, Scheme.BearerToken };
        private static readonly string[] c_HttpRequestHeaders = { "Authorization" };
        private static readonly string[] c_HttpQueryKeys = { "Username", "Password", "Authorization", "Bearer", "Token" };

        public LocalAuthentication()
        {
            if ( ! File.Exists( m_AuthFile ) )
            {
                AuthLocalFile NewFile = new AuthLocalFile
                {
                    Users = new User[]
                    {
                        new User { Enabled = false, Username = "admin", Password = "password", Tokens = new Token[] { new Token { Value = "ABCDE", Expiry = string.Empty } } }
                    }
                };

                WriteFile(NewFile);
            }
            else
            {
                try
                {
                    AuthLocalFile AuthFileRoot = ReadFile();

                    if(AuthFileRoot != null)
                    {
                        // Upgrade Legacy Files.
                        if( AuthFileRoot.isLegacy )
                        {
                            WriteFile(AuthFileRoot);
                        }
                    }
                }
                catch (Exception)
                {
                }
            }
        }
        public IReadOnlyCollection<string> Domains
        {
            get
            {
                return Array.AsReadOnly( c_Domains);
            }
        }

        public IReadOnlyCollection<string> HttpRequestHeaders
        {
            get
            {
                return Array.AsReadOnly(c_HttpRequestHeaders);
            }
        }

        public IReadOnlyCollection<string> HttpQueryKeys
        {
            get
            {
                return Array.AsReadOnly(c_HttpQueryKeys);
            }
        }

        public IReadOnlyCollection<Scheme> Schemes
        {
            get
            {
                return Array.AsReadOnly(c_Schemes);
            }
        }

        private IAuthResult doLookUp(AuthLocalFile AuthFileRoot, string Token)
        {
            User UserSearch = AuthFileRoot.Users.FirstOrDefault(User =>
            {
                if (User.Tokens != null)
                {
                    return (User.Tokens.FirstOrDefault(T => T.Value == Token) != null) ? true : false;
                }
                else
                {
                    return false;
                }
            });

            if( UserSearch != null)
            {
                return new AuthResult { Result = true, Identity = c_Domains[0] + "\\" + UserSearch.Username, Message = "OK" };
            }
            else
            {
                return new AuthResult { Result = false, Message = string.Empty };
            }
        }

        private IAuthResult doLookUp(AuthLocalFile AuthFileRoot, string Username, string Password )
        {
            User UserSearch = AuthFileRoot.Users.FirstOrDefault(u => u.Username.Equals(Username, StringComparison.OrdinalIgnoreCase));

            if (UserSearch == null)
            {
                return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
            }
            else
            {
                if (!UserSearch.Enabled)
                {
                    return new AuthResult { Result = false, Message = "User is disabled" };
                }
                else
                {
                    if (UserSearch.Password != Password)
                    {
                        return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                    }
                    else
                    {
                        return new AuthResult { Result = true, Identity = c_Domains[0] + "\\" + UserSearch.Username, Message = "OK" };
                    }
                }
            }
        }


        private AuthLocalFile ReadFile()
        {
            XmlSerializer Serializer = new XmlSerializer(typeof(AuthLocalFile));
            using (Stream stream = new FileStream(m_AuthFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                return (AuthLocalFile)Serializer.Deserialize(stream);
            }
        }

        private void  WriteFile(AuthLocalFile theFileObject)
        {
            XmlAttributeOverrides overrides = new XmlAttributeOverrides();

            XmlAttributes attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("UsersLegacy"));
            overrides.Add(typeof(AuthLocalFile), "UsersLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("UsernameLegacy"));
            overrides.Add(typeof(User), "UsernameLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("PasswordLegacy"));
            overrides.Add(typeof(User), "PasswordLegacy", attribs);

            attribs = new XmlAttributes();
            attribs.XmlIgnore = true;
            attribs.XmlElements.Add(new XmlElementAttribute("EnabledLegacy"));
            overrides.Add(typeof(User), "EnabledLegacy", attribs);

            try
            {
                XmlSerializer Serializer = new XmlSerializer(typeof(AuthLocalFile), overrides);
                using (Stream stream = new FileStream(m_AuthFile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    Serializer.Serialize(stream, theFileObject);
                }
            }
            catch { }
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
                AuthFileRoot = ReadFile();
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

            if( theCredentials.Scheme == Scheme.Form)
            {
                if(AuthFileRoot.Users == null)
                {
                    return new AuthResult { Result = false, Message = "System Error: Lookup file contains no users" };
                }

                var UserSearch = AuthFileRoot.Users.FirstOrDefault(u => u.Username.Equals(theCredentials.Username, StringComparison.OrdinalIgnoreCase));

                if (UserSearch == null)
                {
                    return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                }
                else
                {
                    if (!UserSearch.Enabled)
                    {
                        return new AuthResult { Result = false, Message = "User is disabled" };
                    }
                    else
                    {
                        if (UserSearch.Password != theCredentials.Password)
                        {
                            return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                        }
                        else
                        {
                            return new AuthResult { Result = true, Identity = c_Domains[0] + "\\" + UserSearch.Username, Message = "OK" };
                        }
                    }
                }
            }
            else if( theCredentials.Scheme == Scheme.Basic && theCredentials.HttpRequestHeaders != null)
            {
                KeyValuePair<string, IEnumerable<string>> AuthorizationHeader = theCredentials.HttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

                if(AuthorizationHeader.Equals( new KeyValuePair<string, IEnumerable<string>>() ) )
                {
                    return new AuthResult { Result = false, Message = "Missing Authorization Header" };
                }

                if (AuthorizationHeader.Value != null && AuthorizationHeader.Value.Count() > 0)
                {
                    string EncodedValue = AuthorizationHeader.Value.First();
                    string DecodedValue = Encoding.UTF8.GetString(Convert.FromBase64String(EncodedValue));
                    string DomainAndUsername = DecodedValue.Substring(0, DecodedValue.IndexOf(":"));
                    string Password = DecodedValue.Substring(DecodedValue.IndexOf(":") + 1);

                    int IndexOfSlash = DomainAndUsername.IndexOf("\\");

                    string Domain;
                    string Username;

                    if (IndexOfSlash != -1)
                    {
                        Domain = DomainAndUsername.Substring(0, IndexOfSlash);
                        Username = DomainAndUsername.Substring(IndexOfSlash + 1);
                    }
                    else
                    {
                        return new AuthResult { Result = false, Message = "Missing Domain" };
                    }

                    if(Domain.Equals(c_Domains[0], StringComparison.OrdinalIgnoreCase))
                    {
                        return doLookUp(AuthFileRoot, Username, Password);
                    }
                    else
                    {
                        return new AuthResult { Result = false, Message = "Domain mismatch" };
                    }
                }
                else
                {
                    return new AuthResult { Result = false, Message = "Missing value in Authorization Header" };
                }
            }
            else if (theCredentials.Scheme == Scheme.BearerToken && theCredentials.HttpRequestHeaders != null)
            {
                KeyValuePair<string, IEnumerable<string>> AuthorizationHeader = theCredentials.HttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

                if (AuthorizationHeader.Equals(new KeyValuePair<string, IEnumerable<string>>()))
                {
                    return new AuthResult { Result = false, Message = "Missing Authorization Header" };
                }

                if (AuthorizationHeader.Value != null && AuthorizationHeader.Value.Count() > 0)
                {
                    return doLookUp(AuthFileRoot, AuthorizationHeader.Value.First());
                }
                else
                {
                    return new AuthResult { Result = false, Message = "Missing value in Authorization Header" };
                }
            }
            else
            {
                return new AuthResult { Result = false, Message = "Not a supported Scheme" };
            }
        }
    }
}
