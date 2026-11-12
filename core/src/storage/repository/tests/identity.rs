use super::*;

#[tokio::test]
async fn identity_repository_find_by_type_and_name() {
    let db = test_db().await;
    let repo = IdentityRepository::new(db);

    let mut personal = sample_identity("personal one");
    personal.tags = vec!["tag-a".to_string()];
    personal
        .attributes
        .insert("dept".to_string(), "eng".to_string());
    repo.create(&personal).await.unwrap();

    let mut work = Identity::new("work one".to_string(), IdentityType::Work);
    work.email = Some("work@example.com".to_string());
    repo.create(&work).await.unwrap();

    assert_eq!(repo.find_all().await.unwrap().len(), 2);
    assert_eq!(
        repo.find_by_type(&IdentityType::Work).await.unwrap().len(),
        1
    );
    let by_name = repo.find_by_name("personal one").await.unwrap().unwrap();
    assert_eq!(by_name.tags, vec!["tag-a".to_string()]);
    assert_eq!(
        by_name.attributes.get("dept").map(String::as_str),
        Some("eng")
    );
    assert!(repo.find_by_name("ghost").await.unwrap().is_none());
}

#[tokio::test]
async fn identity_travel_marked_round_trips() {
    let db = test_db().await;
    let repo = IdentityRepository::new(db);

    let mut marked = sample_identity("travel light");
    assert!(!marked.travel_marked, "new identities default unmarked");
    marked.travel_marked = true;
    repo.create(&marked).await.unwrap();

    let fetched = repo.find_by_name("travel light").await.unwrap().unwrap();
    assert!(fetched.travel_marked);

    // update 路径同样保列
    let mut flipped = fetched.clone();
    flipped.travel_marked = false;
    repo.update(&flipped).await.unwrap();
    let refetched = repo.find_by_id(&marked.id).await.unwrap().unwrap();
    assert!(!refetched.travel_marked);
}
