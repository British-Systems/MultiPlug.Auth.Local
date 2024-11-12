using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using MultiPlug.Base.Security;
using MultiPlug.Auth.Local.Models;
using MultiPlug.Auth.Local.Models.File;
using MultiPlug.Auth.Local.File;

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
            if ( FileManager.Exists() )
            {
                try
                {
                    FileBody AuthFileRoot = FileManager.Read();

                    // Upgrade Legacy Files.
                    if( AuthFileRoot.isLegacy )
                    {
                        FileManager.Write(AuthFileRoot);
                    }
                }
                catch (Exception)
                {
                }
            }
        }

        public IAuthResult Add(IAuthCredentials theCredentials)
        {
            FileBody File = FileManager.Read();

            var UserSearch = File.Users.FirstOrDefault(User => User.Username != null ? User.Username.Equals(theCredentials.Username, StringComparison.OrdinalIgnoreCase) : false);

            if (UserSearch == null)
            {
                FileToken[] Tokens = new FileToken[0];

                var AuthHeader = GetAuthHeader(theCredentials.HttpRequestHeaders);
                var AuthFriendlyName = GetAuthFriendlyNameHeader(theCredentials.HttpRequestHeaders);

                if (AuthHeader != null && AuthFriendlyName != null && AuthHeader.Length == AuthFriendlyName.Length)
                {
                    Tokens = new FileToken[AuthHeader.Length];

                    for (int i = 0; i < AuthHeader.Length; i++)
                    {
                        Tokens[i] = new FileToken { Value = AuthHeader[i], Expiry = string.Empty, FriendlyName = AuthFriendlyName[i] };
                    }
                }

                var NewUser = new FileUser { Enabled = true, Username = theCredentials.Username, Password = Utils.Passwords.GenerateSaltedPassword(theCredentials.Username + theCredentials.Password), Tokens = Tokens };

                FileManager.AddUser(File, NewUser);
                FileManager.Write(File);
                return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(NewUser), NewUser.Enabled, ConstructTokenFriendlyNameList(NewUser)) };
            }
            else
            {
                return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)), Message = "Duplicate User" };
            }
        }

        public IAuthResult Edit(IAuthCredentials theCredentials, IAuthCredentials theNewCredentials)
        {
            FileBody File = FileManager.Read();

            var UserSearch = File.Users.FirstOrDefault(User => User.Username.Equals(theCredentials.Username, StringComparison.OrdinalIgnoreCase));

            if(UserSearch != null)
            {
                // Change of Username or Password require Current Password to be Okay
                if ((!string.IsNullOrEmpty(theNewCredentials.Username)) || (!string.IsNullOrEmpty(theNewCredentials.Password)))
                {
                    if (Utils.Passwords.AuthenticatePassword(theCredentials.Username + theCredentials.Password, UserSearch.Password))
                    {
                        if (!string.IsNullOrEmpty(theNewCredentials.Username)) // Change of Username
                        {
                            var DuplicateUserSearch = File.Users.FirstOrDefault(User => User.Username.Equals(theNewCredentials.Username, StringComparison.OrdinalIgnoreCase));

                            if (DuplicateUserSearch != null)
                            {
                                return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(DuplicateUserSearch), DuplicateUserSearch.Enabled, ConstructTokenFriendlyNameList(DuplicateUserSearch)), Message = "Duplicate User" };
                            }

                            UserSearch.Username = theNewCredentials.Username;
                            // We have to update the Salted password as it's based on the Username
                            UserSearch.Password = Utils.Passwords.GenerateSaltedPassword(theNewCredentials.Username + (string.IsNullOrEmpty(theNewCredentials.Password) ? theCredentials.Password : theNewCredentials.Password));
                        }
                        else if (!string.IsNullOrEmpty(theNewCredentials.Password)) // Change of Password
                        {
                            UserSearch.Password = Utils.Passwords.GenerateSaltedPassword(theCredentials.Username + theNewCredentials.Password);
                        }

                        FileManager.Write(File);
                        return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)) };
                    }
                    else
                    {
                        return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)), Message = "Incorrect Current Password" };
                    }
                }
                else
                {
                    // New Tokens
                    var AuthHeader = GetAuthHeader(theNewCredentials.HttpRequestHeaders);
                    var AuthFriendlyName = GetAuthFriendlyNameHeader(theNewCredentials.HttpRequestHeaders);

                    if (AuthHeader != null && AuthFriendlyName != null && AuthHeader.Length == AuthFriendlyName.Length)
                    {
                        var NewTokens = new FileToken[AuthHeader.Length];

                        for (int i = 0; i < AuthHeader.Length; i++)
                        {
                            NewTokens[i] = new FileToken { Value = AuthHeader[i], Expiry = string.Empty, FriendlyName = AuthFriendlyName[i] };
                        }

                        FileManager.AddTokens(UserSearch, NewTokens);
                        FileManager.Write(File);
                        return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch).ToArray()) };
                    }
                    else
                    {
                        return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)), Message = "Not Modified" };
                    }
                }
            }
            else
            {
                return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(theCredentials.Username), false, new string[0]), Message = "User not found" };
            }
        }

        public IAuthResult Delete(IAuthCredentials theCredentials)
        {
            FileBody File = FileManager.Read();

            var UserSearch = File.Users.FirstOrDefault(User => User.Username.Equals(theCredentials.Username, StringComparison.OrdinalIgnoreCase));

            if (UserSearch != null)
            {
                var AuthFriendlyName = GetAuthFriendlyNameHeader(theCredentials.HttpRequestHeaders);

                if(AuthFriendlyName != null)
                {
                    if( ! FileManager.RemoveTokens(UserSearch, AuthFriendlyName))
                    {
                        return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)), Message = "Token Not Found" };
                    }
                }
                else
                {
                    FileManager.DeleteUser(File, UserSearch);
                }

                FileManager.Write(File);
                return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)) };
            }
            else
            {
                return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(theCredentials.Username), false, new string[0]), Message = "User not found" };
            }
        }

        public IReadOnlyCollection<IUser> Users()
        {
            FileBody File = FileManager.Read();
            return Array.AsReadOnly(File == null || File.Users == null ? new AUser[0] : File.Users.Select(User => new AUser(ConstructFullUsername(User), User.Enabled, ConstructTokenFriendlyNameList(User)) ).ToArray());
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

        private IAuthResult doTokenLookUp(FileBody AuthFileRoot, string Token)
        {
            FileUser UserSearch = AuthFileRoot.Users.FirstOrDefault(User =>
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
                if (!UserSearch.Enabled)
                {
                    return new AuthResult { Result = false, Message = "User is disabled" };
                }
                else
                {
                    return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, ConstructTokenFriendlyNameList(UserSearch)), Message = "OK" };
                }
            }
            else
            {
                return new AuthResult { Result = false, Message = string.Empty };
            }
        }

        private string ConstructFullUsername(FileUser theUser)
        {
            return c_Domains[0] + "\\" + theUser.Username;
        }

        private string ConstructFullUsername(string theUser)
        {
            return c_Domains[0] + "\\" + theUser;
        }

        private string[] ConstructTokenFriendlyNameList(FileUser theUser)
        {
            return theUser.Tokens == null ? new string[0] : theUser.Tokens.Select(t => t.FriendlyName).ToArray();
        }

        private IAuthResult doLookUp(FileBody AuthFileRoot, string Username, string Password )
        {
            FileUser UserSearch = AuthFileRoot.Users.FirstOrDefault(u => u.Username.Equals(Username, StringComparison.OrdinalIgnoreCase));

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
                    if( Utils.Passwords.AuthenticatePassword(Username + Password, UserSearch.Password ) )
                    {
                        return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, UserSearch.Tokens.Select(t => t.FriendlyName).ToArray()), Message = "OK" };
                    }
                    else
                    {
                        return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                    }
                }
            }
        }

        public IAuthResult Authenticate( IAuthCredentials theCredentials)
        {
            FileBody AuthFileRoot = null;

            if (!FileManager.Exists())
            {
                return new AuthResult(false, null, "System Error: User file does not exist");
            }

            string[] AuthorizationHeader = null;

            AuthFileRoot = FileManager.Read();

            switch (theCredentials.Scheme)
            {
                case Scheme.Form:
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
                            if (Utils.Passwords.AuthenticatePassword(theCredentials.Username + theCredentials.Password, UserSearch.Password))
                            {
                                return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, UserSearch.Tokens.Select(t => t.FriendlyName).ToArray()), Message = "OK" };
                            }
                            else
                            {
                                return new AuthResult { Result = false, Message = "Username or Password is incorrect" };
                            }
                        }
                    }

                case Scheme.Basic:
                    AuthorizationHeader = GetAuthHeader(theCredentials.HttpRequestHeaders);

                    if (AuthorizationHeader == null)
                    {
                        return new AuthResult { Result = false, Message = "Missing Authorization Header" };
                    }

                    string EncodedValue = AuthorizationHeader.First();
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

                    if (Domain.Equals(c_Domains[0], StringComparison.OrdinalIgnoreCase))
                    {
                        return doLookUp(AuthFileRoot, Username, Password);
                    }
                    else
                    {
                        return new AuthResult { Result = false, Message = "Domain mismatch" };
                    }

                case Scheme.BearerToken:
                    AuthorizationHeader = GetAuthHeader(theCredentials.HttpRequestHeaders);

                    if (AuthorizationHeader == null)
                    {
                        return new AuthResult { Result = false, Message = "Missing Authorization Header" };
                    }

                    return doTokenLookUp(AuthFileRoot, AuthorizationHeader.First());

                default:
                    return new AuthResult { Result = false, Message = "Not a Supported Authentication Scheme" };
            }
        }

        public IAuthResult Enable(string theUser, bool isEnabled)
        {
            FileBody File = FileManager.Read();

            var UserSearch = File.Users.FirstOrDefault(User => User.Username.Equals(theUser, StringComparison.OrdinalIgnoreCase));

            if (UserSearch != null)
            {
                if(UserSearch.Enabled != isEnabled)
                {
                    UserSearch.Enabled = isEnabled;
                    FileManager.Write(File);
                    return new AuthResult { Result = true, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, UserSearch.Tokens.Select(t => t.FriendlyName).ToArray()), Message = "OK" };
                }
                else
                {
                    return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(UserSearch), UserSearch.Enabled, UserSearch.Tokens.Select(t => t.FriendlyName).ToArray()), Message = "Not Modified" };
            }
            }
            else
            {
                return new AuthResult { Result = false, User = new AUser(ConstructFullUsername(theUser), UserSearch.Enabled, UserSearch.Tokens.Select(t => t.FriendlyName).ToArray()), Message = "User not found" };
            }
        }

        private string[] GetAuthHeader(IEnumerable<KeyValuePair<string, IEnumerable<string>>> theHttpRequestHeaders)
        {
            if(theHttpRequestHeaders == null)
            {
                return null;
            }

            var Search = theHttpRequestHeaders.FirstOrDefault(Header => Header.Key == c_HttpRequestHeaders[0]);

            if(Search.Equals(default(KeyValuePair<string, IEnumerable<string>>)))
            {
                return null;
            }
            else
            {
                return Search.Value.ToArray();
            }
        }

        private string[] GetAuthFriendlyNameHeader(IEnumerable<KeyValuePair<string, IEnumerable<string>>> theHttpRequestHeaders)
        {
            if (theHttpRequestHeaders == null)
            {
                return null;
            }

            var Search = theHttpRequestHeaders.FirstOrDefault(Header => Header.Key == "AuthorizationFriendlyName");

            if (Search.Equals(default(KeyValuePair<string, IEnumerable<string>>)))
            {
                return null;
            }
            else
            {
                return Search.Value.ToArray();
            }
        }
    }
}
