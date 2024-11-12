using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models.File
{
    public class FileToken
    {
        [XmlAttribute("token")]
        public string Value { get; set; }
        [XmlAttribute("expiry")]
        public string Expiry { get; set; }
        [XmlAttribute("name")]
        public string FriendlyName { get; set; }
    }
}
