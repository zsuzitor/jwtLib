# https://hub.docker.com/_/microsoft-dotnet
FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /app

# copy csproj and restore as distinct layers
#COPY *.csproj .
COPY  ["jwtLib/jwtLib.csproj", "."]
RUN dotnet restore

# copy and publish app and libraries
#COPY . ./
COPY ["jwtLib", "./"]
#что бы не запускать тут билд отдельной командой, надо добавить игнор на все bin obj папки и другой мусор
#RUN dotnet build  -o /app/out
RUN dotnet publish -c release -o /app/out --no-restore

# final stage/image
FROM mcr.microsoft.com/dotnet/runtime:3.1
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "jwtLib.dll"]