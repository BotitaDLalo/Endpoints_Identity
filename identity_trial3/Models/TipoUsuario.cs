using System.ComponentModel.DataAnnotations;

namespace identity_trial3.Models
{
    public class TipoUsuario
    {
        [Key]
        public int TipoUsuarioId { get; set; }
        public required string Usuario { get; set; }
    }
}
