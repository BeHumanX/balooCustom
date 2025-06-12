package db

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const (
	MongoDBURI       = "mongodb://localhost:27017"
	DatabaseName     = "goProxyConfig"
	CollectionName   = "configurations"
	ConfigDocumentID = "main_config"
)

var (
	Client     *mongo.Client
	Collection *mongo.Collection
)

func init() {
	// Establish MongoDB connection when the package is initialized
	fmt.Println("Connecting to MongoDB...")
	clientOptions := options.Client().ApplyURI(MongoDBURI)
	var err error
	Client, err = mongo.Connect(clientOptions)
	if err != nil {
		panic(fmt.Errorf("failed to connect to MongoDB: %v", err))
	}

	// Ping the primary to verify connection
	err = Client.Ping(context.Background(), readpref.Primary())
	if err != nil {
		panic(fmt.Errorf("failed to ping MongoDB: %v", err))
	}

	Collection = Client.Database(DatabaseName).Collection(CollectionName)
	fmt.Println("MongoDB connection established successfully.")
}

func Close() {
	if Client != nil {
		err := Client.Disconnect(context.Background())
		if err != nil {
			fmt.Printf("Error closing MongoDB connection: %v\n", err)
		} else {
			fmt.Println("MongoDB connection closed.")
		}
	}
}
