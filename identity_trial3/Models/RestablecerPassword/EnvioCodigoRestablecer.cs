using System.ComponentModel.DataAnnotations;

namespace identity_trial3.Models.RestablecerPassword
{
    public class EnvioCodigoRestablecer
    {
        public required string Destinatario { get; set; }
    }
}
