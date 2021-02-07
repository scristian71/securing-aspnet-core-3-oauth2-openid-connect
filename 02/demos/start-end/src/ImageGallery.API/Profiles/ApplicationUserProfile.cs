using AutoMapper;

namespace ImageGallery.API.Profiles
{
    public class ApplicationUserProfile : Profile
    {
        public ApplicationUserProfile()
        {
            CreateMap<Model.ApplicationUserProfile, Entities.ApplicationUserProfile>().ReverseMap();

            CreateMap<Model.ApplicationUserProfileForCreation, Entities.ApplicationUserProfile>()
               .ForMember(m => m.Id, options => options.Ignore())
               .ForMember(m => m.Subject, options => options.Ignore())
               .ForMember(m => m.SubscriptionLevel, options => options.Ignore());
        }
    }
}
