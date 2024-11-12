using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models.File
{
    public class FileUser
    {
        [XmlAttribute("username")]
        public string Username { get; set; }
        [XmlAttribute("Username")]
        public string UsernameLegacy { get { return this.Username; } set { this.Username = value; } }
        [XmlAttribute("password")]
        public string Password { get; set; }
        [XmlAttribute("Password")]
        public string PasswordLegacy { get { return this.Password; } set { this.Password = value; } }
        [XmlAttribute("enabled")]
        public bool Enabled { get; set; }
        [XmlAttribute("Enabled")]
        public bool EnabledLegacy { get { return this.Enabled; } set { this.Enabled = value; } }
        [XmlArray("tokens")]
        [XmlArrayItem("add")]
        public FileToken[] Tokens { get; set; }
    }
}
