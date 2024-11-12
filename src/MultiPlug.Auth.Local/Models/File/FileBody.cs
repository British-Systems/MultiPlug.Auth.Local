using System;
using System.Xml.Serialization;

namespace MultiPlug.Auth.Local.Models.File
{
    [Serializable]
    [XmlRoot(ElementName = "MultiPlug.Auth.Local")]
    public class FileBody
    {
        [XmlIgnore]
        public bool isLegacy { get; set; }

        [XmlArray("users")]
        [XmlArrayItem("add")]
        public FileUser[] Users { get; set; }

        [XmlArray("Users")]
        [XmlArrayItem("User")]
        public FileUser[] UsersLegacy { get { return this.Users; } set { this.Users = value; isLegacy = true; } }
    }
}
