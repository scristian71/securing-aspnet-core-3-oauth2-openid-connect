FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src

# Copy csproj and restore as distinct layers

COPY *.csproj ./ImageGallery.Client/
COPY ./ImageGallery.Model/*.csproj ./ImageGallery.Model/
WORKDIR /src/ImageGallery.Client/
RUN dotnet restore

# Copy everything else and build

WORKDIR /src
COPY . ./ImageGallery.Client/
COPY ./ImageGallery.Model/. ./ImageGallery.Model/
WORKDIR /src/ImageGallery.Client/
RUN dotnet build -c Release -o /app/build

# publish

FROM build AS publish
WORKDIR /src/ImageGallery.Client/
RUN dotnet publish -c Release -o /app/publish

# Build runtime image

FROM mcr.microsoft.com/dotnet/aspnet:3.1
#FROM baseaspcore
WORKDIR /app
EXPOSE 5001
ENV ASPNETCORE_URLS=https://*:5001
ENV ASPNETCORE_Kestrel__Certificates__Default__Password=password
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/live/certificate.pfx
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "ImageGallery.Client.dll"]
